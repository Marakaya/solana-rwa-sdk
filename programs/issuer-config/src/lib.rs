use anchor_lang::prelude::*;

declare_id!("BytoP9j6ZS6jcPPX3JWzxdRtSyN7RMsf55A9gYE5XWta");

#[program]
pub mod issuer_config {
    use super::*;

    /// Инициализирует конфиг для нового compliant-токена
    pub fn initialize_token_config(
        ctx: Context<InitializeTokenConfig>,
        registry: Pubkey,
        rules: RulesConfig,
    ) -> Result<()> {
        let config = &mut ctx.accounts.token_config;
        config.mint = ctx.accounts.mint.key();
        config.authority = ctx.accounts.authority.key();
        config.registry = registry;
        config.paused = false;
        config.rules = rules;
        config.bump = ctx.bumps.token_config;

        let holders_count = &mut ctx.accounts.holders_count;
        holders_count.mint = ctx.accounts.mint.key();
        holders_count.count = 0;
        holders_count.bump = ctx.bumps.holders_count;

        emit!(TokenConfigured {
            mint: config.mint,
            authority: config.authority,
            registry,
        });

        Ok(())
    }

    /// Обновляет compliance-правила без передеплоя
    pub fn update_rules(ctx: Context<UpdateConfig>, rules: RulesConfig) -> Result<()> {
        ctx.accounts.token_config.rules = rules;
        emit!(RulesUpdated { mint: ctx.accounts.token_config.mint });
        Ok(())
    }

    /// Экстренная пауза всех трансферов
    pub fn pause(ctx: Context<UpdateConfig>) -> Result<()> {
        require!(!ctx.accounts.token_config.paused, RwaError::AlreadyPaused);
        ctx.accounts.token_config.paused = true;
        emit!(TransfersPaused { mint: ctx.accounts.token_config.mint });
        Ok(())
    }

    /// Снимает паузу
    pub fn unpause(ctx: Context<UpdateConfig>) -> Result<()> {
        require!(ctx.accounts.token_config.paused, RwaError::NotPaused);
        ctx.accounts.token_config.paused = false;
        emit!(TransfersUnpaused { mint: ctx.accounts.token_config.mint });
        Ok(())
    }

    /// Добавляет кошелёк инвестора в whitelist
    pub fn whitelist_investor(ctx: Context<WhitelistInvestor>) -> Result<()> {
        let record = &mut ctx.accounts.holder_record;
        record.wallet = ctx.accounts.investor.key();
        record.mint = ctx.accounts.token_config.mint;
        record.whitelisted = true;
        record.first_received_at = 0; // заполняется при первом получении
        record.bump = ctx.bumps.holder_record;

        emit!(InvestorWhitelisted {
            mint: ctx.accounts.token_config.mint,
            wallet: ctx.accounts.investor.key(),
        });

        Ok(())
    }

    /// Убирает инвестора из whitelist
    pub fn remove_investor(ctx: Context<ManageInvestor>) -> Result<()> {
        ctx.accounts.holder_record.whitelisted = false;

        emit!(InvestorRemoved {
            mint: ctx.accounts.token_config.mint,
            wallet: ctx.accounts.holder_record.wallet,
        });

        Ok(())
    }

    /// Обновляет время первого получения токенов (вызывается из transfer-hook)
    pub fn record_first_receipt(ctx: Context<RecordFirstReceipt>, timestamp: i64) -> Result<()> {
        let record = &mut ctx.accounts.holder_record;
        if record.first_received_at == 0 {
            record.first_received_at = timestamp;
        }
        Ok(())
    }

    /// Принудительный трансфер (burn + mint) для регуляторных случаев
    /// Использует burn+mint вместо transfer — transfer-hook не вызывается
    pub fn forced_transfer(
        ctx: Context<ForcedTransfer>,
        amount: u64,
    ) -> Result<()> {
        require!(!ctx.accounts.token_config.paused, RwaError::TransfersPaused);
        require!(amount > 0, RwaError::ZeroAmount);

        // Записываем first_received_at для получателя если нужно
        let clock = Clock::get()?;
        let receiver_record = &mut ctx.accounts.receiver_holder_record;
        if receiver_record.first_received_at == 0 {
            receiver_record.first_received_at = clock.unix_timestamp;
        }

        emit!(ForcedTransferExecuted {
            mint: ctx.accounts.token_config.mint,
            from: ctx.accounts.from_holder_record.wallet,
            to: ctx.accounts.receiver_holder_record.wallet,
            amount,
        });

        // Фактический burn + mint через Token-2022 будет добавлен в следующей итерации
        // когда подключим anchor-spl с token-2022 features
        msg!("ForcedTransfer: {} tokens from {:?} to {:?}",
            amount,
            ctx.accounts.from_holder_record.wallet,
            ctx.accounts.receiver_holder_record.wallet,
        );

        Ok(())
    }
}

// ─── Account Structures ───────────────────────────────────────────────────────

/// Главный конфиг токена — один на каждый mint
#[account]
pub struct TokenConfig {
    pub mint: Pubkey,
    pub authority: Pubkey,    // issuer
    pub registry: Pubkey,     // Identity Registry программа
    pub paused: bool,
    pub rules: RulesConfig,
    pub bump: u8,
}

impl TokenConfig {
    // discriminator(8) + mint(32) + authority(32) + registry(32)
    // + paused(1) + RulesConfig::LEN + bump(1)
    pub const LEN: usize = 8 + 32 + 32 + 32 + 1 + RulesConfig::LEN + 1;
}

/// Compliance-правила — все настраиваются без передеплоя
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct RulesConfig {
    pub require_whitelist: bool,
    pub max_balance: u64,            // 0 = без лимита (investor cap)
    pub max_holders: u32,            // 0 = без лимита (Reg D: 2000)
    pub lockup_duration: i64,        // секунды после first_received_at; 0 = нет
    pub min_transfer_amount: u64,    // 0 = нет минимума
    pub allowed_jurisdictions: [[u8; 2]; 10], // пустые = разрешены все
    pub blocked_jurisdictions: [[u8; 2]; 10], // пустые = никто не заблокирован
    pub required_investor_type: u8,  // 0=any, 1=accredited+, 2=institutional only
    pub kyc_grace_period: i64,       // секунды grace после истечения KYC
}

impl RulesConfig {
    // require_whitelist(1) + max_balance(8) + max_holders(4) + lockup_duration(8)
    // + min_transfer_amount(8) + allowed_jurisdictions(20) + blocked_jurisdictions(20)
    // + required_investor_type(1) + kyc_grace_period(8)
    pub const LEN: usize = 1 + 8 + 4 + 8 + 8 + 20 + 20 + 1 + 8;
}

/// Запись о каждом держателе токена
#[account]
pub struct HolderRecord {
    pub wallet: Pubkey,
    pub mint: Pubkey,
    pub whitelisted: bool,
    pub first_received_at: i64,  // для lockup; 0 = ещё не получал
    pub bump: u8,
}

impl HolderRecord {
    // discriminator(8) + wallet(32) + mint(32) + whitelisted(1)
    // + first_received_at(8) + bump(1)
    pub const LEN: usize = 8 + 32 + 32 + 1 + 8 + 1;
}

/// Счётчик уникальных держателей (для Reg D max_holders)
#[account]
pub struct HoldersCount {
    pub mint: Pubkey,
    pub count: u32,
    pub bump: u8,
}

impl HoldersCount {
    // discriminator(8) + mint(32) + count(4) + bump(1)
    pub const LEN: usize = 8 + 32 + 4 + 1;
}

// ─── Instruction Contexts ─────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeTokenConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = TokenConfig::LEN,
        seeds = [b"config", mint.key().as_ref()],
        bump,
    )]
    pub token_config: Account<'info, TokenConfig>,

    #[account(
        init,
        payer = authority,
        space = HoldersCount::LEN,
        seeds = [b"holders_count", mint.key().as_ref()],
        bump,
    )]
    pub holders_count: Account<'info, HoldersCount>,

    /// CHECK: Token-2022 mint — только читаем pubkey
    pub mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(
        mut,
        seeds = [b"config", token_config.mint.as_ref()],
        bump = token_config.bump,
        has_one = authority,
    )]
    pub token_config: Account<'info, TokenConfig>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct WhitelistInvestor<'info> {
    #[account(
        seeds = [b"config", token_config.mint.as_ref()],
        bump = token_config.bump,
        has_one = authority,
    )]
    pub token_config: Account<'info, TokenConfig>,

    #[account(
        init,
        payer = authority,
        space = HolderRecord::LEN,
        seeds = [b"holder", token_config.mint.as_ref(), investor.key().as_ref()],
        bump,
    )]
    pub holder_record: Account<'info, HolderRecord>,

    /// CHECK: кошелёк инвестора
    pub investor: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ManageInvestor<'info> {
    #[account(
        seeds = [b"config", token_config.mint.as_ref()],
        bump = token_config.bump,
        has_one = authority,
    )]
    pub token_config: Account<'info, TokenConfig>,

    #[account(
        mut,
        seeds = [b"holder", token_config.mint.as_ref(), holder_record.wallet.as_ref()],
        bump = holder_record.bump,
    )]
    pub holder_record: Account<'info, HolderRecord>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RecordFirstReceipt<'info> {
    #[account(
        seeds = [b"config", token_config.mint.as_ref()],
        bump = token_config.bump,
    )]
    pub token_config: Account<'info, TokenConfig>,

    #[account(
        mut,
        seeds = [b"holder", token_config.mint.as_ref(), holder_record.wallet.as_ref()],
        bump = holder_record.bump,
    )]
    pub holder_record: Account<'info, HolderRecord>,

    /// CHECK: вызывается из transfer-hook программы
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct ForcedTransfer<'info> {
    #[account(
        seeds = [b"config", token_config.mint.as_ref()],
        bump = token_config.bump,
        has_one = authority,
    )]
    pub token_config: Account<'info, TokenConfig>,

    #[account(
        seeds = [b"holder", token_config.mint.as_ref(), from_holder_record.wallet.as_ref()],
        bump = from_holder_record.bump,
    )]
    pub from_holder_record: Account<'info, HolderRecord>,

    #[account(
        mut,
        seeds = [b"holder", token_config.mint.as_ref(), receiver_holder_record.wallet.as_ref()],
        bump = receiver_holder_record.bump,
    )]
    pub receiver_holder_record: Account<'info, HolderRecord>,

    pub authority: Signer<'info>,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct TokenConfigured {
    pub mint: Pubkey,
    pub authority: Pubkey,
    pub registry: Pubkey,
}

#[event]
pub struct RulesUpdated {
    pub mint: Pubkey,
}

#[event]
pub struct TransfersPaused {
    pub mint: Pubkey,
}

#[event]
pub struct TransfersUnpaused {
    pub mint: Pubkey,
}

#[event]
pub struct InvestorWhitelisted {
    pub mint: Pubkey,
    pub wallet: Pubkey,
}

#[event]
pub struct InvestorRemoved {
    pub mint: Pubkey,
    pub wallet: Pubkey,
}

#[event]
pub struct ForcedTransferExecuted {
    pub mint: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum RwaError {
    #[msg("Transfers are paused for this token")]
    TransfersPaused,
    #[msg("Token is already paused")]
    AlreadyPaused,
    #[msg("Token is not paused")]
    NotPaused,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
}
