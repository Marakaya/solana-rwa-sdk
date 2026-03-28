use anchor_lang::prelude::*;

declare_id!("3DWG7C87tM8fPWjPC9tcJpHZuLHC8xXNoEeXibU73PHy");

#[program]
pub mod solana_rwa_sdk {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
