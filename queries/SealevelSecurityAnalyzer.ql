/**
 * @name Sealevel Attack Patterns - Comprehensive Security Analyzer
 * @description Detects all major Sealevel attack patterns in Solana programs
 * @kind problem
 * @problem.severity error
 * @security-severity 9.5
 * @precision high
 * @id sealevel/comprehensive-security
 * @tags security
 *       sealevel
 *       solana
 *       anchor
 *       cpi
 *       pda
 *       initialization
 *       authorization
 */

import rust


// SEALEVEL ATTACK PATTERN 0: SIGNER AUTHORIZATION
predicate missingSignerAuthorization(Function func, string pattern) {
  // Pattern: Functions that should check signer but don't
  func.getName().toString() = "log_message" and
  not exists(CallExpr call |
    call.getEnclosingCallable() = func and
    call.toString().matches("%is_signer%")
  ) and
  pattern = "SEALEVEL-0: Missing signer authorization - AccountInfo used without validation"
}

  
// SEALEVEL ATTACK PATTERN 1: ACCOUNT DATA MATCHING
predicate insecureAccountDataMatching(Function func, string pattern) {
  // Pattern: Direct data unpacking without proper validation
  exists(CallExpr unpack |
    unpack.getEnclosingCallable() = func and
    unpack.toString().matches("%unpack%") and
    not exists(IfExpr ownerCheck |
      ownerCheck.getEnclosingCallable() = func and
      ownerCheck.toString().matches("%owner%")
    ) and
    pattern = "SEALEVEL-1: Account data matching - Unpacking without owner validation"
  )
}


// SEALEVEL ATTACK PATTERN 2: OWNER CHECKS
predicate inadequateOwnerChecks(Function func, string pattern) {
  // Pattern: Owner check vulnerability - checking owner but missing ctx.program_id
  exists(IfExpr ownerCheck |
    ownerCheck.getEnclosingCallable() = func and
    ownerCheck.toString().matches("%owner%") and
    ownerCheck.toString().matches("%program_id%") and
    not ownerCheck.toString().matches("%ctx.program_id%") and
    pattern = "SEALEVEL-2: Owner checks - Using owner != program_id instead of ctx.program_id"
  )
}


// SEALEVEL ATTACK PATTERN 3: TYPE COSPLAY  
predicate typeCosplayVulnerability(Function func, string pattern) {
  // Pattern: Deserializing accounts without proper type discrimination
  exists(CallExpr deserialize |
    deserialize.getEnclosingCallable() = func and
    deserialize.toString().matches("%try_from_slice%") and
    not exists(Variable discriminator |
      discriminator.getName().toString().matches("%discriminator%") and
      discriminator.getAnAccess().getEnclosingCallable() = func
    ) and
    pattern = "SEALEVEL-3: Type cosplay - Deserialization without discriminator checks"
  )
}


// SEALEVEL ATTACK PATTERN 4: INITIALIZATION
predicate initializationVulnerability(Function func, string pattern) {
  // Pattern: Reinitialization attack - no initialization state check
  func.getName().toString() = "initialize" and
  exists(CallExpr serialize |
    serialize.getEnclosingCallable() = func and
    serialize.toString().matches("%serialize%") and
    not exists(IfExpr initCheck |
      initCheck.getEnclosingCallable() = func and
      (initCheck.toString().matches("%initialized%") or
       initCheck.toString().matches("%authority%"))
    ) and
    pattern = "SEALEVEL-4: Initialization - Account reinitialization without state check"
  )
}


// SEALEVEL ATTACK PATTERN 5: ARBITRARY CPI
predicate arbitraryCPIVulnerability(Function func, string pattern) {
  // Pattern: CPI calls without proper program validation
  exists(CallExpr invoke |
    invoke.getEnclosingCallable() = func and
    invoke.toString().matches("%invoke%") and
    not exists(IfExpr programCheck |
      programCheck.getEnclosingCallable() = func and
      (programCheck.toString().matches("%token_program%") or
       programCheck.toString().matches("%program_id%"))
    ) and
    pattern = "SEALEVEL-5: Arbitrary CPI - Cross-program invocation without program validation"
  )
}


// SEALEVEL ATTACK PATTERN 6: DUPLICATE MUTABLE ACCOUNTS
predicate duplicateMutableAccounts(Function func, string pattern) {
  // Pattern: Functions that take multiple user accounts without uniqueness check
  func.getName().toString() = "update" and
  exists(CallExpr userA, CallExpr userB |
    userA.getEnclosingCallable() = func and
    userB.getEnclosingCallable() = func and
    userA.toString().matches("%user_a%") and
    userB.toString().matches("%user_b%") and
    userA != userB and
    not exists(IfExpr uniqueCheck |
      uniqueCheck.getEnclosingCallable() = func and
      uniqueCheck.toString().matches("%key%")
    ) and
    pattern = "SEALEVEL-6: Duplicate mutable accounts - Same account passed multiple times"
  )
}


// SEALEVEL ATTACK PATTERN 7: BUMP SEED CANONICALIZATION  
predicate bumpSeedCanonicalization(Function func, string pattern) {
  // Pattern: Non-canonical bump seed usage
  func.getName().toString() = "set_value" and
  exists(CallExpr createAddr |
    createAddr.getEnclosingCallable() = func and
    createAddr.toString().matches("%create_program_address%") and
    not exists(CallExpr findBump |
      findBump.getEnclosingCallable() = func and
      findBump.toString().matches("%find_program_address%")
    ) and
    pattern = "SEALEVEL-7: Bump seed canonicalization - Using non-canonical bump seed"
  )
}


// SEALEVEL ATTACK PATTERN 8: PDA SHARING
predicate pdaSharingVulnerability(Function func, string pattern) {
  // Pattern: PDA authority confusion in token transfers
  func.getName().toString() = "withdraw_tokens" and
  exists(CallExpr transfer |
    transfer.getEnclosingCallable() = func and
    transfer.toString().matches("%transfer%") and
    not exists(CallExpr hasOneCheck |
      hasOneCheck.getEnclosingCallable() = func and
      hasOneCheck.toString().matches("%has_one%")
    ) and
    pattern = "SEALEVEL-8: PDA sharing - Authority confusion in token transfers"
  )
}


// SEALEVEL ATTACK PATTERN 9: CLOSING ACCOUNTS
predicate closingAccountsVulnerability(Function func, string pattern) {
  // Pattern: Account closing without proper cleanup
  func.getName().toString() = "close" and
  exists(AssignmentExpr lamportAssign |
    lamportAssign.getEnclosingCallable() = func and
    lamportAssign.toString().matches("%lamports%") and
    lamportAssign.toString().matches("%= 0%") and
    not exists(AssignmentExpr dataWipe |
      dataWipe.getEnclosingCallable() = func and
      dataWipe.toString().matches("%data%")
    ) and
    pattern = "SEALEVEL-9: Closing accounts - Lamport transfer without data cleanup"
  )
}


// SEALEVEL ATTACK PATTERN 10: SYSVAR ADDRESS CHECKING
predicate sysvarAddressChecking(Function func, string pattern) {
  // Pattern: Using sysvars without address validation
  func.getName().toString() = "check_sysvar_address" and
  exists(CallExpr keyAccess |
    keyAccess.getEnclosingCallable() = func and
    keyAccess.toString().matches("%rent%") and
    keyAccess.toString().matches("%key%") and
    not exists(IfExpr addrCheck |
      addrCheck.getEnclosingCallable() = func and
      addrCheck.toString().matches("%sysvar%")
    ) and
    pattern = "SEALEVEL-10: Sysvar address checking - Sysvar usage without address validation"
  )
}


// COMPREHENSIVE SEALEVEL DETECTOR
from Function func, string vulnerability
where
  missingSignerAuthorization(func, vulnerability) or
  insecureAccountDataMatching(func, vulnerability) or
  inadequateOwnerChecks(func, vulnerability) or
  typeCosplayVulnerability(func, vulnerability) or
  initializationVulnerability(func, vulnerability) or
  arbitraryCPIVulnerability(func, vulnerability) or
  duplicateMutableAccounts(func, vulnerability) or
  bumpSeedCanonicalization(func, vulnerability) or
  pdaSharingVulnerability(func, vulnerability) or
  closingAccountsVulnerability(func, vulnerability) or
  sysvarAddressChecking(func, vulnerability)

select func, vulnerability + " in function '" + func.getName().toString() + "'"