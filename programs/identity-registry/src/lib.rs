use anchor_lang::prelude::*;

declare_id!("AumHWNchd7WXhsASUDsHp2mZZtsmFGcRvMrFWk3MLL6V");

#[program]
pub mod identity_registry {
    use super::*;

    /// Инициализирует новый Identity Registry для KYC-провайдера
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.total_identities = 0;
        registry.bump = ctx.bumps.registry;
        msg!("Identity Registry initialized by: {:?}", registry.authority);
        Ok(())
    }

    /// Добавляет новую identity (после KYC-верификации)
    pub fn add_identity(
        ctx: Context<AddIdentity>,
        status: u8,
        investor_type: u8,
        jurisdiction: [u8; 2],
        kyc_expiry: i64,
    ) -> Result<()> {
        require!(ComplianceStatus::try_from(status).is_ok(), RwaError::InvalidStatus);
        require!(InvestorType::try_from(investor_type).is_ok(), RwaError::InvalidInvestorType);

        let clock = Clock::get()?;
        let registry = &mut ctx.accounts.registry;
        let record = &mut ctx.accounts.identity_record;

        record.wallet = ctx.accounts.wallet.key();
        record.registry = registry.key();
        record.status = status;
        record.investor_type = investor_type;
        record.jurisdiction = jurisdiction;
        record.kyc_expiry = kyc_expiry;
        record.added_at = clock.unix_timestamp;
        record.bump = ctx.bumps.identity_record;

        registry.total_identities = registry.total_identities.saturating_add(1);

        emit!(IdentityAdded {
            wallet: record.wallet,
            status,
            investor_type,
            jurisdiction,
        });

        Ok(())
    }

    /// Обновляет существующую identity (ре-KYC, смена статуса)
    pub fn update_identity(
        ctx: Context<UpdateIdentity>,
        status: u8,
        investor_type: u8,
        jurisdiction: [u8; 2],
        kyc_expiry: i64,
    ) -> Result<()> {
        require!(ComplianceStatus::try_from(status).is_ok(), RwaError::InvalidStatus);
        require!(InvestorType::try_from(investor_type).is_ok(), RwaError::InvalidInvestorType);

        let record = &mut ctx.accounts.identity_record;
        let prev_status = record.status;

        record.status = status;
        record.investor_type = investor_type;
        record.jurisdiction = jurisdiction;
        record.kyc_expiry = kyc_expiry;

        emit!(IdentityUpdated {
            wallet: record.wallet,
            prev_status,
            new_status: status,
        });

        Ok(())
    }

    /// Отзывает identity — блокирует кошелёк навсегда
    pub fn revoke_identity(ctx: Context<RevokeIdentity>) -> Result<()> {
        let record = &mut ctx.accounts.identity_record;
        record.status = ComplianceStatus::Revoked as u8;

        emit!(IdentityRevoked { wallet: record.wallet });

        Ok(())
    }
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

#[account]
#[derive(Default)]
pub struct RegistryState {
    pub authority: Pubkey,       // KYC-провайдер (единственный, кто может добавлять/менять)
    pub total_identities: u64,
    pub bump: u8,
}

impl RegistryState {
    // discriminator(8) + authority(32) + total_identities(8) + bump(1)
    pub const LEN: usize = 8 + 32 + 8 + 1;
}

#[account]
pub struct IdentityRecord {
    pub wallet: Pubkey,
    pub registry: Pubkey,
    pub status: u8,            // ComplianceStatus
    pub investor_type: u8,     // InvestorType
    pub jurisdiction: [u8; 2], // ISO 3166-1 alpha-2, e.g. [b'U', b'S']
    pub kyc_expiry: i64,       // unix timestamp; 0 = без срока
    pub added_at: i64,
    pub bump: u8,
}

impl IdentityRecord {
    // discriminator(8) + wallet(32) + registry(32) + status(1) + investor_type(1)
    // + jurisdiction(2) + kyc_expiry(8) + added_at(8) + bump(1)
    pub const LEN: usize = 8 + 32 + 32 + 1 + 1 + 2 + 8 + 8 + 1;

    /// Sender-проверка: verified + KYC не истёк (с учётом grace period)
    pub fn is_valid_sender(&self, now: i64, grace_period: i64) -> bool {
        if self.status != ComplianceStatus::Verified as u8 {
            return false;
        }
        if self.kyc_expiry == 0 {
            return true;
        }
        now < self.kyc_expiry + grace_period
    }

    /// Receiver-проверка: только статус (expiry не проверяем — нельзя заморозить получение)
    pub fn is_valid_receiver(&self) -> bool {
        self.status == ComplianceStatus::Verified as u8
    }
}

// ─── Enums ────────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Pending = 0,
    Verified = 1,
    Suspended = 2,
    Revoked = 3,
}

impl TryFrom<u8> for ComplianceStatus {
    type Error = ();
    fn try_from(v: u8) -> std::result::Result<Self, ()> {
        match v {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Verified),
            2 => Ok(Self::Suspended),
            3 => Ok(Self::Revoked),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InvestorType {
    Retail = 0,
    Accredited = 1,
    Institutional = 2,
}

impl TryFrom<u8> for InvestorType {
    type Error = ();
    fn try_from(v: u8) -> std::result::Result<Self, ()> {
        match v {
            0 => Ok(Self::Retail),
            1 => Ok(Self::Accredited),
            2 => Ok(Self::Institutional),
            _ => Err(()),
        }
    }
}

// ─── Instruction Contexts ─────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = RegistryState::LEN,
        seeds = [b"registry", authority.key().as_ref()],
        bump,
    )]
    pub registry: Account<'info, RegistryState>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AddIdentity<'info> {
    #[account(
        mut,
        seeds = [b"registry", registry.authority.as_ref()],
        bump = registry.bump,
        has_one = authority,
    )]
    pub registry: Account<'info, RegistryState>,

    #[account(
        init,
        payer = authority,
        space = IdentityRecord::LEN,
        seeds = [b"identity", registry.key().as_ref(), wallet.key().as_ref()],
        bump,
    )]
    pub identity_record: Account<'info, IdentityRecord>,

    /// CHECK: кошелёк инвестора — только читаем pubkey
    pub wallet: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateIdentity<'info> {
    #[account(
        seeds = [b"registry", registry.authority.as_ref()],
        bump = registry.bump,
        has_one = authority,
    )]
    pub registry: Account<'info, RegistryState>,

    #[account(
        mut,
        seeds = [b"identity", registry.key().as_ref(), identity_record.wallet.as_ref()],
        bump = identity_record.bump,
    )]
    pub identity_record: Account<'info, IdentityRecord>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RevokeIdentity<'info> {
    #[account(
        seeds = [b"registry", registry.authority.as_ref()],
        bump = registry.bump,
        has_one = authority,
    )]
    pub registry: Account<'info, RegistryState>,

    #[account(
        mut,
        seeds = [b"identity", registry.key().as_ref(), identity_record.wallet.as_ref()],
        bump = identity_record.bump,
    )]
    pub identity_record: Account<'info, IdentityRecord>,

    pub authority: Signer<'info>,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct IdentityAdded {
    pub wallet: Pubkey,
    pub status: u8,
    pub investor_type: u8,
    pub jurisdiction: [u8; 2],
}

#[event]
pub struct IdentityUpdated {
    pub wallet: Pubkey,
    pub prev_status: u8,
    pub new_status: u8,
}

#[event]
pub struct IdentityRevoked {
    pub wallet: Pubkey,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum RwaError {
    #[msg("Invalid compliance status value")]
    InvalidStatus,
    #[msg("Invalid investor type value")]
    InvalidInvestorType,
}
