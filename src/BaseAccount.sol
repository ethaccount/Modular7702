// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-empty-blocks */
/* solhint-disable no-inline-assembly */

import "aa-0.8/interfaces/IAccount.sol";
import "aa-0.8/interfaces/IEntryPoint.sol";
import "aa-0.8/utils/Exec.sol";
import "aa-0.8/core/UserOperationLib.sol";
import "./interfaces/IERC7579Account.sol";
import "./lib/ModeLib.sol";
import "./lib/ExecLib.sol";

abstract contract BaseAccount is IAccount, IERC7579Account {
    using UserOperationLib for PackedUserOperation;
    using ModeLib for ExecutionMode;
    using ExecLib for bytes;

    error ExecuteError(uint256 index, bytes error);
    error NotFromEntryPoint();
    error NotFromEntryPointOrSelf();

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint()), NotFromEntryPoint());
        _;
    }

    modifier onlyEntryPointOrSelf() {
        require(msg.sender == address(entryPoint()) || msg.sender == address(this), NotFromEntryPointOrSelf());
        _;
    }

    function entryPoint() public view virtual returns (IEntryPoint);

    // ================================================ Validation ================================================

    /// @inheritdoc IAccount
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        override
        onlyEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateUserOp(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /**
     * Validate the signature is valid for this message.
     * @param userOp          - Validate the userOp.signature field.
     * @param userOpHash      - Convenient field: the hash of the request, to check the signature against.
     *                          (also hashes the entrypoint and chain id)
     * @return validationData - Signature and time-range of this operation.
     *                          <20-byte> aggregatorOrSigFail - 0 for valid signature, 1 to mark signature failure,
     *                                    otherwise, an address of an aggregator contract.
     *                          <6-byte> validUntil - Last timestamp this operation is valid at, or 0 for "indefinitely"
     *                          <6-byte> validAfter - first timestamp this operation is valid
     *                          If the account doesn't use time-range, it is enough to return
     *                          SIG_VALIDATION_FAILED value (1) for signature failure.
     *                          Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        returns (uint256 validationData);

    /**
     * Sends to the entrypoint (msg.sender) the missing funds for this transaction.
     * SubClass MAY override this method for better funds management
     * (e.g. send to the entryPoint more than the minimum required, so that in future transactions
     * it will not be required to send again).
     * @param missingAccountFunds - The minimum value this method should send the entrypoint.
     *                              This value MAY be zero, in case there is enough deposit,
     *                              or the userOp has a paymaster.
     */
    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success);
            // Ignore failure (its EntryPoint's job to verify, not account.)
        }
    }

    // ================================================ Execution ================================================

    function execute(ExecutionMode mode, bytes calldata executionCalldata) external payable onlyEntryPoint {
        (CallType callType, ExecType execType) = mode.decodeBasic();
        if (callType == CALLTYPE_SINGLE && execType == EXECTYPE_DEFAULT) {
            (address target, uint256 value, bytes calldata callData) = executionCalldata.decodeSingle();
            _execute(target, value, callData);
        } else if (callType == CALLTYPE_BATCH && execType == EXECTYPE_DEFAULT) {
            Execution[] calldata executions = executionCalldata.decodeBatch();
            _executeBatch(executions);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    function _requireExecutorModule() public view virtual;

    function executeFromExecutor(ExecutionMode mode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        _requireExecutorModule();
        (CallType callType, ExecType execType) = mode.decodeBasic();
        if (callType == CALLTYPE_SINGLE && execType == EXECTYPE_DEFAULT) {
            (address target, uint256 value, bytes calldata callData) = executionCalldata.decodeSingle();
            _execute(target, value, callData);
        } else if (callType == CALLTYPE_BATCH && execType == EXECTYPE_DEFAULT) {
            Execution[] calldata executions = executionCalldata.decodeBatch();
            _executeBatch(executions);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    /**
     * execute a single call from the account.
     */
    function _execute(address target, uint256 value, bytes calldata data) internal {
        bool ok = Exec.call(target, value, data, gasleft());
        if (!ok) {
            Exec.revertWithReturnData();
        }
    }

    /**
     * execute a batch of calls.
     * revert on the first call that fails.
     * If the batch reverts, and it contains more than a single call, then wrap the revert with ExecuteError,
     *  to mark the failing call index.
     */
    function _executeBatch(Execution[] calldata calls) internal {
        uint256 callsLength = calls.length;
        for (uint256 i = 0; i < callsLength; i++) {
            Execution calldata call = calls[i];
            bool ok = Exec.call(call.target, call.value, call.callData, gasleft());
            if (!ok) {
                if (callsLength == 1) {
                    Exec.revertWithReturnData();
                } else {
                    revert ExecuteError(i, Exec.getReturnData(0));
                }
            }
        }
    }
}
