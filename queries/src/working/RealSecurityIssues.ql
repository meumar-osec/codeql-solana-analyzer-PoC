/**
 * @name Real Solana security vulnerabilities
 * @description Detect actual security issues in Solana programs using working patterns
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id solana/real-security-issues
 * @tags security
 *       solana
 *       anchor
 *       production
 */

import rust

// Missing signer validation in transfer functions
predicate missingSignerInTransfer(CallExpr transferCall, Function func) {
  transferCall.getEnclosingCallable() = func and
  transferCall.getFunction().toString().matches("%transfer%") and
  (
    transferCall.getFunction().toString().matches("%spl%") or
    transferCall.getFunction().toString().matches("%anchor_spl%")
  ) and
  func.getName().toString().matches("%transfer%") and
  // No signer validation in function
  not exists(PathExpr path |
    path.getEnclosingCallable() = func and
    (
      path.toString().matches("%Signer%") or
      path.toString().matches("%is_signer%") or
      path.toString().matches("%authority%")
    )
  )
}

// Initialization without discriminator check
predicate initWithoutDiscriminator(Function func) {
  func.getName().toString().matches("%init%") and
  not exists(PathExpr path |
    path.getEnclosingCallable() = func and
    path.toString().matches("%discriminator%")
  ) and
  // Has state modification
  exists(AssignmentExpr assign |
    assign.getEnclosingCallable() = func
  )
}

// Unsafe arithmetic in financial calculations
predicate unsafeArithmetic(BinaryExpr binExpr, Function func) {
  binExpr.getEnclosingCallable() = func and
  (binExpr.getOperator() = "+" or binExpr.getOperator() = "*") and
  (
    func.getName().toString().matches("%swap%") or
    func.getName().toString().matches("%price%") or
    func.getName().toString().matches("%fee%") or
    func.getName().toString().matches("%amount%")
  ) and
  // No checked arithmetic
  not exists(CallExpr call |
    call.getEnclosingCallable() = func and
    call.getFunction().toString().matches("%checked_%")
  )
}

// CPI without program validation
predicate cpiWithoutValidation(CallExpr cpiCall, Function func) {
  cpiCall.getEnclosingCallable() = func and
  cpiCall.getFunction().toString().matches("%invoke%") and
  // No program validation
  not exists(CallExpr requireCall |
    requireCall.getEnclosingCallable() = func and
    requireCall.getFunction().toString().matches("%require%") and
    requireCall.getArgList().getAnArg().toString().matches("%program%")
  )
}

from AstNode issue, Function func, string message
where
  (
    missingSignerInTransfer(issue, func) and
    message = "Transfer operation lacks signer validation - unauthorized transfers possible"
  ) or (
    initWithoutDiscriminator(func) and issue = func and
    message = "Initialization function vulnerable to reinitialization attacks"
  ) or (
    unsafeArithmetic(issue, func) and
    message = "Arithmetic operation may overflow in financial calculation"
  ) or (
    cpiWithoutValidation(issue, func) and
    message = "Cross-program invocation without target program validation"
  )
select issue, message + " in function '" + func.getName().toString() + "'"