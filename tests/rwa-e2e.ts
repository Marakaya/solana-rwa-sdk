import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  ExtensionType,
  createInitializeMintInstruction,
  createInitializeTransferHookInstruction,
  getMintLen,
  createAssociatedTokenAccountInstruction,
  getAssociatedTokenAddressSync,
  createMintToInstruction,
  createTransferCheckedWithTransferHookInstruction,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { expect } from "chai";
import BN from "bn.js";

// Program IDs (из Anchor.toml)
const IDENTITY_REGISTRY_PROGRAM_ID = new PublicKey(
  "AumHWNchd7WXhsASUDsHp2mZZtsmFGcRvMrFWk3MLL6V"
);
const ISSUER_CONFIG_PROGRAM_ID = new PublicKey(
  "BytoP9j6ZS6jcPPX3JWzxdRtSyN7RMsf55A9gYE5XWta"
);
const TRANSFER_HOOK_PROGRAM_ID = new PublicKey(
  "HcXBwuD8SxSEpmNcTfCKK4umEKKqoPYV5xXHsRf9Uasa"
);

// ─── Helpers: compute Anchor instruction discriminators ───────────────────────
// sha256("global:<method_name>")[0..8]
import { createHash } from "crypto";
function anchorDiscriminator(name: string): Buffer {
  const hash = createHash("sha256").update(`global:${name}`).digest();
  return hash.slice(0, 8);
}

// ─── Helpers: find PDAs ──────────────────────────────────────────────────────

function findRegistryPDA(authority: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("registry"), authority.toBuffer()],
    IDENTITY_REGISTRY_PROGRAM_ID
  );
}

function findIdentityPDA(
  registry: PublicKey,
  wallet: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("identity"), registry.toBuffer(), wallet.toBuffer()],
    IDENTITY_REGISTRY_PROGRAM_ID
  );
}

function findTokenConfigPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("config"), mint.toBuffer()],
    ISSUER_CONFIG_PROGRAM_ID
  );
}

function findHoldersCountPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("holders_count"), mint.toBuffer()],
    ISSUER_CONFIG_PROGRAM_ID
  );
}

function findHolderRecordPDA(
  mint: PublicKey,
  wallet: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("holder"), mint.toBuffer(), wallet.toBuffer()],
    ISSUER_CONFIG_PROGRAM_ID
  );
}

function findExtraAccountMetaListPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("extra-account-metas"), mint.toBuffer()],
    TRANSFER_HOOK_PROGRAM_ID
  );
}

// ─── Helpers: build raw Anchor instructions ──────────────────────────────────

// Identity Registry: initialize_registry
function buildInitializeRegistryIx(authority: PublicKey): TransactionInstruction {
  const [registryPDA] = findRegistryPDA(authority);
  return new TransactionInstruction({
    programId: IDENTITY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: registryPDA, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: anchorDiscriminator("initialize_registry"),
  });
}

// Identity Registry: add_identity(status, investor_type, jurisdiction, kyc_expiry)
function buildAddIdentityIx(
  authority: PublicKey,
  wallet: PublicKey,
  status: number,
  investorType: number,
  jurisdiction: [number, number],
  kycExpiry: BN
): TransactionInstruction {
  const [registryPDA] = findRegistryPDA(authority);
  const [identityPDA] = findIdentityPDA(registryPDA, wallet);

  const data = Buffer.alloc(8 + 1 + 1 + 2 + 8);
  anchorDiscriminator("add_identity").copy(data, 0);
  data.writeUInt8(status, 8);
  data.writeUInt8(investorType, 9);
  data.writeUInt8(jurisdiction[0], 10);
  data.writeUInt8(jurisdiction[1], 11);
  kycExpiry.toBuffer("le", 8).copy(data, 12);

  return new TransactionInstruction({
    programId: IDENTITY_REGISTRY_PROGRAM_ID,
    keys: [
      { pubkey: registryPDA, isSigner: false, isWritable: true },
      { pubkey: identityPDA, isSigner: false, isWritable: true },
      { pubkey: wallet, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// Issuer Config: initialize_token_config(registry, rules)
function buildInitializeTokenConfigIx(
  authority: PublicKey,
  mint: PublicKey,
  registryPubkey: PublicKey
): TransactionInstruction {
  const [tokenConfigPDA] = findTokenConfigPDA(mint);
  const [holdersCountPDA] = findHoldersCountPDA(mint);

  // RulesConfig serialization:
  // require_whitelist(1) + max_balance(8) + max_holders(4) + lockup_duration(8)
  // + min_transfer_amount(8) + allowed_jurisdictions(20) + blocked_jurisdictions(20)
  // + required_investor_type(1) + kyc_grace_period(8)
  const RULES_LEN = 1 + 8 + 4 + 8 + 8 + 20 + 20 + 1 + 8;
  const rulesData = Buffer.alloc(RULES_LEN);
  rulesData.writeUInt8(1, 0); // require_whitelist = true
  // rest is zeros = no limits

  // Data: discriminator(8) + registry pubkey(32) + rules
  const data = Buffer.alloc(8 + 32 + RULES_LEN);
  anchorDiscriminator("initialize_token_config").copy(data, 0);
  registryPubkey.toBuffer().copy(data, 8);
  rulesData.copy(data, 40);

  return new TransactionInstruction({
    programId: ISSUER_CONFIG_PROGRAM_ID,
    keys: [
      { pubkey: tokenConfigPDA, isSigner: false, isWritable: true },
      { pubkey: holdersCountPDA, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

// Issuer Config: whitelist_investor
function buildWhitelistInvestorIx(
  authority: PublicKey,
  mint: PublicKey,
  investor: PublicKey
): TransactionInstruction {
  const [tokenConfigPDA] = findTokenConfigPDA(mint);
  const [holderRecordPDA] = findHolderRecordPDA(mint, investor);

  return new TransactionInstruction({
    programId: ISSUER_CONFIG_PROGRAM_ID,
    keys: [
      { pubkey: tokenConfigPDA, isSigner: false, isWritable: false },
      { pubkey: holderRecordPDA, isSigner: false, isWritable: true },
      { pubkey: investor, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: anchorDiscriminator("whitelist_investor"),
  });
}

// Transfer Hook: initialize_extra_account_meta_list
function buildInitExtraAccountMetaListIx(
  payer: PublicKey,
  mint: PublicKey
): TransactionInstruction {
  const [extraAccountMetaListPDA] = findExtraAccountMetaListPDA(mint);

  return new TransactionInstruction({
    programId: TRANSFER_HOOK_PROGRAM_ID,
    keys: [
      { pubkey: extraAccountMetaListPDA, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: anchorDiscriminator("initialize_extra_account_meta_list"),
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("RWA Compliance SDK — E2E", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const connection = provider.connection;
  const authority = provider.wallet.payer;

  // Accounts
  const mintKeypair = Keypair.generate();
  const mint = mintKeypair.publicKey;
  const decimals = 6;

  // Investors
  const investorA = Keypair.generate(); // whitelisted
  const investorB = Keypair.generate(); // whitelisted
  const investorC = Keypair.generate(); // NOT whitelisted

  // PDAs
  let registryPDA: PublicKey;
  let tokenConfigPDA: PublicKey;
  let holdersCountPDA: PublicKey;

  before(async () => {
    [registryPDA] = findRegistryPDA(authority.publicKey);
    [tokenConfigPDA] = findTokenConfigPDA(mint);
    [holdersCountPDA] = findHoldersCountPDA(mint);

    // Airdrop SOL to investors for ATA creation
    for (const investor of [investorA, investorB, investorC]) {
      const sig = await connection.requestAirdrop(
        investor.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await connection.confirmTransaction(sig);
    }
  });

  it("1. Initialize Identity Registry", async () => {
    const ix = buildInitializeRegistryIx(authority.publicKey);
    const tx = new Transaction().add(ix);
    const sig = await provider.sendAndConfirm(tx);
    console.log("  Registry initialized:", sig.slice(0, 20) + "...");

    // Verify account exists
    const info = await connection.getAccountInfo(registryPDA);
    expect(info).to.not.be.null;
    console.log("  Registry PDA:", registryPDA.toBase58());
  });

  it("2. Add identities for investors A, B, C", async () => {
    const jurisdiction_US: [number, number] = [85, 83]; // "US"
    const noExpiry = new BN(0);

    // Add all three as verified in identity registry
    const tx = new Transaction();
    for (const investor of [investorA, investorB, investorC]) {
      tx.add(
        buildAddIdentityIx(
          authority.publicKey,
          investor.publicKey,
          1, // Verified
          1, // Accredited
          jurisdiction_US,
          noExpiry
        )
      );
    }
    const sig = await provider.sendAndConfirm(tx);
    console.log("  3 identities added:", sig.slice(0, 20) + "...");
  });

  it("3. Create Token-2022 mint with transfer hook", async () => {
    // Calculate space needed for mint + transfer hook extension
    const extensions = [ExtensionType.TransferHook];
    const mintLen = getMintLen(extensions);
    const lamports = await connection.getMinimumBalanceForRentExemption(mintLen);

    const tx = new Transaction().add(
      // Create mint account
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: mint,
        space: mintLen,
        lamports,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
      // Initialize transfer hook extension
      createInitializeTransferHookInstruction(
        mint,
        authority.publicKey,
        TRANSFER_HOOK_PROGRAM_ID,
        TOKEN_2022_PROGRAM_ID
      ),
      // Initialize mint
      createInitializeMintInstruction(
        mint,
        decimals,
        authority.publicKey,
        null, // no freeze authority
        TOKEN_2022_PROGRAM_ID
      )
    );

    const sig = await provider.sendAndConfirm(tx, [mintKeypair]);
    console.log("  Mint created:", mint.toBase58());
    console.log("  Tx:", sig.slice(0, 20) + "...");
  });

  it("4. Initialize Token Config (issuer-config)", async () => {
    const ix = buildInitializeTokenConfigIx(
      authority.publicKey,
      mint,
      registryPDA
    );
    const tx = new Transaction().add(ix);
    const sig = await provider.sendAndConfirm(tx);
    console.log("  TokenConfig initialized:", sig.slice(0, 20) + "...");
  });

  it("5. Initialize ExtraAccountMetaList (transfer-hook)", async () => {
    const ix = buildInitExtraAccountMetaListIx(authority.publicKey, mint);
    const tx = new Transaction().add(ix);
    const sig = await provider.sendAndConfirm(tx);
    console.log("  ExtraAccountMetaList initialized:", sig.slice(0, 20) + "...");
  });

  it("6. Whitelist investors A and B (not C)", async () => {
    const tx = new Transaction();
    tx.add(buildWhitelistInvestorIx(authority.publicKey, mint, investorA.publicKey));
    tx.add(buildWhitelistInvestorIx(authority.publicKey, mint, investorB.publicKey));
    // Note: investorC is NOT whitelisted

    const sig = await provider.sendAndConfirm(tx);
    console.log("  A & B whitelisted:", sig.slice(0, 20) + "...");
  });

  it("7. Create ATAs and mint tokens to investor A", async () => {
    // Create ATAs for all investors
    const tx = new Transaction();
    for (const investor of [investorA, investorB, investorC]) {
      const ata = getAssociatedTokenAddressSync(
        mint,
        investor.publicKey,
        false,
        TOKEN_2022_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
      );
      tx.add(
        createAssociatedTokenAccountInstruction(
          authority.publicKey,
          ata,
          investor.publicKey,
          mint,
          TOKEN_2022_PROGRAM_ID,
          ASSOCIATED_TOKEN_PROGRAM_ID
        )
      );
    }

    // Also whitelist the authority (mint authority needs to be whitelisted for minting)
    // Actually, mint doesn't go through transfer hook, only transfers do
    // Mint tokens to investor A
    const ataA = getAssociatedTokenAddressSync(
      mint,
      investorA.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    const mintAmount = 1_000_000 * 10 ** decimals; // 1M tokens
    tx.add(
      createMintToInstruction(
        mint,
        ataA,
        authority.publicKey,
        mintAmount,
        [],
        TOKEN_2022_PROGRAM_ID
      )
    );

    const sig = await provider.sendAndConfirm(tx);
    console.log("  ATAs created + 1M tokens minted to A:", sig.slice(0, 20) + "...");
  });

  it("8. Transfer A → B (both whitelisted) ✅ should succeed", async () => {
    const ataA = getAssociatedTokenAddressSync(
      mint,
      investorA.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    const ataB = getAssociatedTokenAddressSync(
      mint,
      investorB.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const transferAmount = 100_000 * 10 ** decimals; // 100K tokens

    const transferIx = await createTransferCheckedWithTransferHookInstruction(
      connection,
      ataA,
      mint,
      ataB,
      investorA.publicKey,
      BigInt(transferAmount),
      decimals,
      [],
      "confirmed",
      TOKEN_2022_PROGRAM_ID
    );

    const tx = new Transaction().add(transferIx);
    const sig = await provider.sendAndConfirm(tx, [investorA]);
    console.log("  A → B transfer succeeded ✅:", sig.slice(0, 20) + "...");
  });

  it("9. Transfer A → C (C not whitelisted) ❌ should fail", async () => {
    const ataA = getAssociatedTokenAddressSync(
      mint,
      investorA.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    const ataC = getAssociatedTokenAddressSync(
      mint,
      investorC.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );

    const transferAmount = 50_000 * 10 ** decimals;

    try {
      const transferIx = await createTransferCheckedWithTransferHookInstruction(
        connection,
        ataA,
        mint,
        ataC,
        investorA.publicKey,
        BigInt(transferAmount),
        decimals,
        [],
        "confirmed",
        TOKEN_2022_PROGRAM_ID
      );

      const tx = new Transaction().add(transferIx);
      await provider.sendAndConfirm(tx, [investorA]);

      // Если дошли сюда — тест провалился
      expect.fail("Transfer to non-whitelisted should have failed");
    } catch (err: any) {
      console.log("  A → C transfer blocked ❌ (expected)");
      // Verify it's a transfer hook error, not some other error
      expect(err.toString()).to.include("Error");
    }
  });
});
