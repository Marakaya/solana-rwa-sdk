use anchor_lang::prelude::*;

declare_id!("HcXBwuD8SxSEpmNcTfCKK4umEKKqoPYV5xXHsRf9Uasa");

/// Импортируем типы из соседних программ через их crate
/// Они подключаются как зависимости в Cargo.toml с feature = "cpi"
use issuer_config::{HolderRecord, TokenConfig};
use identity_registry::IdentityRecord;

#[program]
pub mod transfer_hook {
    use super::*;

    /// Инициализирует ExtraAccountMetaList для mint-а.
    /// Вызывается один раз при создании токена.
    /// Token-2022 использует этот список чтобы знать, какие аккаунты
    /// передавать в execute при каждом трансфере.
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        // ExtraAccountMetaList хранит PDAs которые нужны в execute:
        // 0: TokenConfig (issuer-config)
        // 1: HolderRecord sender (issuer-config)
        // 2: HolderRecord receiver (issuer-config)
        // 3: IdentityRecord sender (identity-registry)
        // 4: IdentityRecord receiver (identity-registry)
        // 5: HoldersCount (issuer-config)
        //
        // Полная реализация с ExtraAccountMeta будет добавлена в Week 2
        // когда подключим anchor-spl token-2022 extensions
        msg!("ExtraAccountMetaList initialized for mint: {:?}", ctx.accounts.mint.key());
        Ok(())
    }

    /// Главная функция — вызывается Token-2022 при каждом трансфере.
    /// Проверяет все compliance-правила и возвращает Ok или Err.
    ///
    /// Порядок проверок:
    /// 1. paused?
    /// 2. whitelist (sender + receiver)
    /// 3. receiver balance cap
    /// 4. max holders
    /// 5. lockup period (sender)
    /// 6. min transfer amount
    /// 7. geo-restrictions (receiver)
    /// 8. investor type (receiver)
    /// 9. KYC validity (sender strict, receiver status-only)
    pub fn execute(ctx: Context<Execute>, amount: u64) -> Result<()> {
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

        // 3. Receiver balance cap
        if rules.max_balance > 0 {
            // token account amount будет добавлен когда подключим anchor-spl
            // сейчас проверяем что правило задано
            msg!("Balance cap check: max_balance = {}", rules.max_balance);
        }

        // 4. Max holders (Reg D)
        if rules.max_holders > 0 {
            let is_new_holder = ctx.accounts.receiver_holder.first_received_at == 0;
            if is_new_holder {
                require!(
                    ctx.accounts.holders_count.count < rules.max_holders,
                    TransferHookError::MaxHoldersReached
                );
            }
        }

        // 5. Lockup period (sender)
        if rules.lockup_duration > 0 {
            let first_received = ctx.accounts.sender_holder.first_received_at;
            if first_received > 0 {
                let lockup_end = first_received + rules.lockup_duration;
                require!(now >= lockup_end, TransferHookError::LockupPeriodActive);
            }
        }

        // 6. Min transfer amount
        if rules.min_transfer_amount > 0 {
            require!(amount >= rules.min_transfer_amount, TransferHookError::BelowMinTransferAmount);
        }

        // 7. Geo-restrictions (receiver)
        let receiver_jurisdiction = ctx.accounts.receiver_identity.jurisdiction;
        check_jurisdiction(
            receiver_jurisdiction,
            &rules.allowed_jurisdictions,
            &rules.blocked_jurisdictions,
        )?;

        // 8. Investor type (receiver)
        if rules.required_investor_type > 0 {
            require!(
                ctx.accounts.receiver_identity.investor_type >= rules.required_investor_type,
                TransferHookError::InsufficientInvestorType
            );
        }

        // 9. KYC validity
        // Sender: строгая проверка — статус Verified + KYC не истёк (с grace period)
        require!(
            ctx.accounts.sender_identity.is_valid_sender(now, rules.kyc_grace_period),
            TransferHookError::SenderKycInvalid
        );
        // Receiver: мягкая проверка — только статус (expiry не блокирует получение)
        require!(
            ctx.accounts.receiver_identity.is_valid_receiver(),
            TransferHookError::ReceiverKycInvalid
        );

        msg!("Transfer approved: {} tokens", amount);
        Ok(())
    }
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

    // Если список разрешённых непустой — receiver должен быть в нём
    let has_allowlist = allowed.iter().any(|j| *j != [0u8; 2]);
    if has_allowlist {
        let is_allowed = allowed.iter().any(|j| *j == jurisdiction);
        require!(is_allowed, TransferHookError::JurisdictionNotAllowed);
    }

    Ok(())
}

// ─── Account Structures ───────────────────────────────────────────────────────

#[account]
pub struct ExtraAccountMetaList {
    pub mint: Pubkey,
    pub bump: u8,
}

impl ExtraAccountMetaList {
    pub const LEN: usize = 8 + 32 + 1;
}

// ─── Instruction Contexts ─────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(
        init,
        payer = payer,
        space = ExtraAccountMetaList::LEN,
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: Account<'info, ExtraAccountMetaList>,

    /// CHECK: Token-2022 mint
    pub mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    /// CHECK: source token account (передаётся Token-2022)
    pub source_token_account: UncheckedAccount<'info>,

    /// CHECK: Token-2022 mint
    pub mint: UncheckedAccount<'info>,

    /// CHECK: destination token account (передаётся Token-2022)
    pub destination_token_account: UncheckedAccount<'info>,

    /// CHECK: владелец source token account
    pub owner: UncheckedAccount<'info>,

    /// CHECK: ExtraAccountMetaList PDA
    #[account(
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    // ─── Extra Accounts (из ExtraAccountMetaList) ──────────────────────────

    /// TokenConfig из issuer-config программы
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

    /// IdentityRecord отправителя из identity-registry
    #[account(
        seeds = [b"identity", token_config.registry.as_ref(), owner.key().as_ref()],
        bump = sender_identity.bump,
        seeds::program = identity_registry::ID,
    )]
    pub sender_identity: Account<'info, IdentityRecord>,

    /// IdentityRecord получателя из identity-registry
    #[account(
        seeds = [b"identity", token_config.registry.as_ref(), receiver_identity.wallet.as_ref()],
        bump = receiver_identity.bump,
        seeds::program = identity_registry::ID,
    )]
    pub receiver_identity: Account<'info, IdentityRecord>,

    /// Счётчик держателей для проверки max_holders
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
