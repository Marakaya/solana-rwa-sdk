use anchor_lang::prelude::*;
use anchor_lang::system_program;
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::{ExecuteInstruction, TransferHookInstruction};

use identity_registry::IdentityRecord;
use issuer_config::{HolderRecord, TokenConfig};

declare_id!("HcXBwuD8SxSEpmNcTfCKK4umEKKqoPYV5xXHsRf9Uasa");

/// Transfer Hook Program — вызывается Token-2022 при каждом трансфере.
/// Проверяет все compliance-правила и разрешает/блокирует перевод.
#[program]
pub mod transfer_hook {
    use super::*;

    /// Инициализирует ExtraAccountMetaList для конкретного mint.
    /// Вызывается один раз при создании compliant-токена.
    ///
    /// Token-2022 при каждом трансфере читает этот PDA чтобы знать,
    /// какие дополнительные аккаунты нужно передать в хук.
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        let extra_metas = build_extra_account_metas()?;

        // Считаем размер аккаунта для хранения ExtraAccountMetaList
        let account_size =
            ExtraAccountMetaList::size_of(extra_metas.len()).map_err(|_| ProgramError::InvalidAccountData)?;

        // Аллоцируем аккаунт через system_program
        let lamports = Rent::get()?.minimum_balance(account_size);
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[u8]] = &[
            b"extra-account-metas",
            mint_key.as_ref(),
            &[ctx.bumps.extra_account_meta_list],
        ];

        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.extra_account_meta_list.to_account_info(),
                },
                &[signer_seeds],
            ),
            lamports,
            account_size as u64,
            ctx.program_id,
        )?;

        // Записываем ExtraAccountMetaList в аккаунт
        ExtraAccountMetaList::init::<ExecuteInstruction>(
            &mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?,
            &extra_metas,
        )?;

        msg!(
            "ExtraAccountMetaList initialized for mint: {:?} with {} extra accounts",
            ctx.accounts.mint.key(),
            extra_metas.len()
        );

        Ok(())
    }

    /// Вызывается Token-2022 при каждом трансфере через fallback dispatcher.
    /// Проверяет все 9 compliance-правил.
    ///
    /// Порядок проверок:
    /// 1. paused?
    /// 2. whitelist (sender + receiver)
    /// 3. receiver balance cap
    /// 4. max holders (Reg D)
    /// 5. lockup period (sender)
    /// 6. min transfer amount
    /// 7. geo-restrictions (receiver)
    /// 8. investor type (receiver)
    /// 9. KYC validity (sender strict + grace, receiver status-only)
    pub fn transfer_hook(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
        let config = &ctx.accounts.token_config;
        let rules = &config.rules;
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;

        // 1. Пауза
        require!(!config.paused, TransferHookError::TransfersPaused);

        // 2. Whitelist
        if rules.require_whitelist {
            require!(
                ctx.accounts.sender_holder.whitelisted,
                TransferHookError::SenderNotWhitelisted
            );
            require!(
                ctx.accounts.receiver_holder.whitelisted,
                TransferHookError::ReceiverNotWhitelisted
            );
        }

        // 3. Receiver balance cap (max_balance per wallet)
        if rules.max_balance > 0 {
            // Десериализуем destination token account чтобы получить текущий баланс
            let dest_data = ctx.accounts.destination_token_account.try_borrow_data()?;
            if dest_data.len() >= 72 {
                // SPL Token account layout: offset 64..72 = amount (u64 LE)
                let current_balance = u64::from_le_bytes(
                    dest_data[64..72].try_into().unwrap(),
                );
                require!(
                    current_balance.saturating_add(amount) <= rules.max_balance,
                    TransferHookError::BalanceCapExceeded
                );
            }
        }

        // 4. Max holders (Reg D — e.g. 2000)
        if rules.max_holders > 0 {
            let is_new_holder = ctx.accounts.receiver_holder.first_received_at == 0;
            if is_new_holder {
                require!(
                    ctx.accounts.holders_count.count < rules.max_holders,
                    TransferHookError::MaxHoldersReached
                );
            }
        }

        // 5. Lockup period (sender не может отправлять до lockup_end)
        if rules.lockup_duration > 0 {
            let first_received = ctx.accounts.sender_holder.first_received_at;
            if first_received > 0 {
                let lockup_end = first_received.saturating_add(rules.lockup_duration);
                require!(now >= lockup_end, TransferHookError::LockupPeriodActive);
            }
        }

        // 6. Min transfer amount
        if rules.min_transfer_amount > 0 {
            require!(
                amount >= rules.min_transfer_amount,
                TransferHookError::BelowMinTransferAmount
            );
        }

        // 7. Geo-restrictions (receiver jurisdiction)
        check_jurisdiction(
            ctx.accounts.receiver_identity.jurisdiction,
            &rules.allowed_jurisdictions,
            &rules.blocked_jurisdictions,
        )?;

        // 8. Investor type (receiver must meet minimum tier)
        if rules.required_investor_type > 0 {
            require!(
                ctx.accounts.receiver_identity.investor_type >= rules.required_investor_type,
                TransferHookError::InsufficientInvestorType
            );
        }

        // 9. KYC validity
        // Sender: строгая — Verified + KYC не истёк (с grace period)
        require!(
            ctx.accounts
                .sender_identity
                .is_valid_sender(now, rules.kyc_grace_period),
            TransferHookError::SenderKycInvalid
        );
        // Receiver: мягкая — только статус Verified (без проверки expiry)
        require!(
            ctx.accounts.receiver_identity.is_valid_receiver(),
            TransferHookError::ReceiverKycInvalid
        );

        msg!("RWA transfer approved: {} tokens", amount);
        Ok(())
    }

    /// Fallback instruction handler.
    ///
    /// Token-2022 вызывает transfer hook через spl-transfer-hook-interface
    /// discriminator (не Anchor discriminator). Эта функция маршрутизирует
    /// вызов на нашу transfer_hook instruction.
    pub fn fallback<'info>(
        program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        let instruction = TransferHookInstruction::unpack(data)?;

        match instruction {
            TransferHookInstruction::Execute { amount } => {
                // Anchor discriminator для transfer_hook = sha256("global:transfer_hook")[..8]
                let mut ix_data = vec![220, 57, 220, 152, 126, 125, 97, 168];
                ix_data.extend_from_slice(&amount.to_le_bytes());
                __private::__global::transfer_hook(program_id, accounts, &ix_data)
            }
            _ => Err(ProgramError::InvalidInstructionData.into()),
        }
    }
}

// ─── ExtraAccountMeta seeds builder ───────────────────────────────────────────

/// Строит список ExtraAccountMeta для Token-2022.
///
/// Стандартные аккаунты (0-4) передаются Token-2022 автоматически:
///   [0] source_token_account
///   [1] mint
///   [2] destination_token_account
///   [3] owner (source owner / authority)
///   [4] extra_account_meta_list PDA
///
/// Extra accounts (наши, начинаются с индекса 5 в полном списке):
///   [5]  issuer-config program ID        (fixed pubkey)
///   [6]  identity-registry program ID    (fixed pubkey)
///   [7]  TokenConfig PDA                 (external PDA from issuer-config)
///   [8]  HolderRecord sender PDA         (external PDA from issuer-config)
///   [9]  HolderRecord receiver PDA       (external PDA from issuer-config)
///   [10] IdentityRecord sender PDA       (external PDA from identity-registry)
///   [11] IdentityRecord receiver PDA     (external PDA from identity-registry)
///   [12] HoldersCount PDA                (external PDA from issuer-config)
fn build_extra_account_metas() -> Result<Vec<ExtraAccountMeta>> {
    Ok(vec![
        // Extra #0 (idx 5): issuer-config program ID
        ExtraAccountMeta::new_with_pubkey(&issuer_config::ID, false, false)?,

        // Extra #1 (idx 6): identity-registry program ID
        ExtraAccountMeta::new_with_pubkey(&identity_registry::ID, false, false)?,

        // Extra #2 (idx 7): TokenConfig PDA from issuer-config
        // seeds = ["config", mint], program = extra#0 (issuer-config)
        ExtraAccountMeta::new_external_pda_with_seeds(
            5, // account index of issuer-config program
            &[
                Seed::Literal { bytes: b"config".to_vec() },
                Seed::AccountKey { index: 1 }, // mint
            ],
            false,
            false,
        )?,

        // Extra #3 (idx 8): HolderRecord sender PDA from issuer-config
        // seeds = ["holder", mint, owner]
        ExtraAccountMeta::new_external_pda_with_seeds(
            5, // issuer-config
            &[
                Seed::Literal { bytes: b"holder".to_vec() },
                Seed::AccountKey { index: 1 }, // mint
                Seed::AccountKey { index: 3 }, // owner
            ],
            false,
            false,
        )?,

        // Extra #4 (idx 9): HolderRecord receiver PDA from issuer-config
        // seeds = ["holder", mint, destination_owner]
        // destination owner = bytes 32..64 from destination_token_account data
        ExtraAccountMeta::new_external_pda_with_seeds(
            5, // issuer-config
            &[
                Seed::Literal { bytes: b"holder".to_vec() },
                Seed::AccountKey { index: 1 }, // mint
                Seed::AccountData {
                    account_index: 2, // destination_token_account
                    data_index: 32,   // owner field offset in SPL token account layout
                    length: 32,
                },
            ],
            false,
            false,
        )?,

        // Extra #5 (idx 10): IdentityRecord sender from identity-registry
        // seeds = ["identity", registry, owner]
        // registry = bytes 72..104 from TokenConfig (idx 7)
        ExtraAccountMeta::new_external_pda_with_seeds(
            6, // identity-registry
            &[
                Seed::Literal { bytes: b"identity".to_vec() },
                Seed::AccountData {
                    account_index: 7, // TokenConfig
                    data_index: 72,   // discriminator(8) + mint(32) + authority(32) = offset 72 -> registry
                    length: 32,
                },
                Seed::AccountKey { index: 3 }, // owner
            ],
            false,
            false,
        )?,

        // Extra #6 (idx 11): IdentityRecord receiver from identity-registry
        // seeds = ["identity", registry, receiver_wallet]
        ExtraAccountMeta::new_external_pda_with_seeds(
            6, // identity-registry
            &[
                Seed::Literal { bytes: b"identity".to_vec() },
                Seed::AccountData {
                    account_index: 7, // TokenConfig
                    data_index: 72,   // registry
                    length: 32,
                },
                Seed::AccountData {
                    account_index: 2, // destination_token_account
                    data_index: 32,   // owner
                    length: 32,
                },
            ],
            false,
            false,
        )?,

        // Extra #7 (idx 12): HoldersCount PDA from issuer-config
        // seeds = ["holders_count", mint]
        ExtraAccountMeta::new_external_pda_with_seeds(
            5, // issuer-config
            &[
                Seed::Literal { bytes: b"holders_count".to_vec() },
                Seed::AccountKey { index: 1 }, // mint
            ],
            false,
            false,
        )?,
    ])
}

// ─── Geo-restriction helper ───────────────────────────────────────────────────

fn check_jurisdiction(
    jurisdiction: [u8; 2],
    allowed: &[[u8; 2]; 10],
    blocked: &[[u8; 2]; 10],
) -> Result<()> {
    // Заблокированные юрисдикции имеют приоритет
    for blocked_jur in blocked.iter() {
        if *blocked_jur != [0u8; 2] && *blocked_jur == jurisdiction {
            return Err(TransferHookError::JurisdictionBlocked.into());
        }
    }

    // Если есть allowlist — receiver обязан быть в нём
    let has_allowlist = allowed.iter().any(|j| *j != [0u8; 2]);
    if has_allowlist {
        let is_allowed = allowed.iter().any(|j| *j == jurisdiction);
        require!(is_allowed, TransferHookError::JurisdictionNotAllowed);
    }

    Ok(())
}

// ─── Instruction Contexts ─────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    /// CHECK: PDA для ExtraAccountMetaList — инициализируется через CPI
    #[account(
        mut,
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    /// CHECK: Token-2022 mint
    pub mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Аккаунты для transfer hook execute.
///
/// Стандартные (0-4) — передаются Token-2022 автоматически:
///   [0] source, [1] mint, [2] destination, [3] owner, [4] extra_account_meta_list
///
/// Extra accounts (5-12) — из ExtraAccountMetaList:
///   [5]  issuer_config_program
///   [6]  identity_registry_program
///   [7]  token_config
///   [8]  sender_holder
///   [9]  receiver_holder
///   [10] sender_identity
///   [11] receiver_identity
///   [12] holders_count
#[derive(Accounts)]
pub struct TransferHook<'info> {
    /// CHECK: source token account
    pub source_token_account: UncheckedAccount<'info>,

    /// CHECK: Token-2022 mint
    pub mint: UncheckedAccount<'info>,

    /// CHECK: destination token account
    pub destination_token_account: UncheckedAccount<'info>,

    /// CHECK: owner of source token account
    pub owner: UncheckedAccount<'info>,

    /// CHECK: ExtraAccountMetaList PDA
    #[account(
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    // ─── Extra Accounts (в порядке из build_extra_account_metas) ──────────

    /// CHECK: issuer-config program ID
    #[account(address = issuer_config::ID)]
    pub issuer_config_program: UncheckedAccount<'info>,

    /// CHECK: identity-registry program ID
    #[account(address = identity_registry::ID)]
    pub identity_registry_program: UncheckedAccount<'info>,

    /// TokenConfig PDA из issuer-config
    #[account(
        seeds = [b"config", mint.key().as_ref()],
        bump = token_config.bump,
        seeds::program = issuer_config::ID,
    )]
    pub token_config: Account<'info, TokenConfig>,

    /// HolderRecord отправителя
    #[account(
        seeds = [b"holder", mint.key().as_ref(), owner.key().as_ref()],
        bump = sender_holder.bump,
        seeds::program = issuer_config::ID,
    )]
    pub sender_holder: Account<'info, HolderRecord>,

    /// HolderRecord получателя
    #[account(
        seeds = [b"holder", mint.key().as_ref(), receiver_holder.wallet.as_ref()],
        bump = receiver_holder.bump,
        seeds::program = issuer_config::ID,
    )]
    pub receiver_holder: Account<'info, HolderRecord>,

    /// IdentityRecord отправителя
    #[account(
        seeds = [b"identity", token_config.registry.as_ref(), owner.key().as_ref()],
        bump = sender_identity.bump,
        seeds::program = identity_registry::ID,
    )]
    pub sender_identity: Account<'info, IdentityRecord>,

    /// IdentityRecord получателя
    #[account(
        seeds = [b"identity", token_config.registry.as_ref(), receiver_identity.wallet.as_ref()],
        bump = receiver_identity.bump,
        seeds::program = identity_registry::ID,
    )]
    pub receiver_identity: Account<'info, IdentityRecord>,

    /// Счётчик уникальных держателей
    #[account(
        seeds = [b"holders_count", mint.key().as_ref()],
        bump = holders_count.bump,
        seeds::program = issuer_config::ID,
    )]
    pub holders_count: Account<'info, issuer_config::HoldersCount>,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum TransferHookError {
    #[msg("Transfers are paused for this token")]
    TransfersPaused,
    #[msg("Sender is not whitelisted")]
    SenderNotWhitelisted,
    #[msg("Receiver is not whitelisted")]
    ReceiverNotWhitelisted,
    #[msg("Transfer would exceed receiver's maximum balance")]
    BalanceCapExceeded,
    #[msg("Maximum number of holders reached (Reg D limit)")]
    MaxHoldersReached,
    #[msg("Tokens are still in lock-up period")]
    LockupPeriodActive,
    #[msg("Transfer amount is below minimum")]
    BelowMinTransferAmount,
    #[msg("Receiver's jurisdiction is blocked")]
    JurisdictionBlocked,
    #[msg("Receiver's jurisdiction is not in the allowed list")]
    JurisdictionNotAllowed,
    #[msg("Receiver does not meet required investor type")]
    InsufficientInvestorType,
    #[msg("Sender KYC is expired or invalid")]
    SenderKycInvalid,
    #[msg("Receiver KYC status is invalid")]
    ReceiverKycInvalid,
}
