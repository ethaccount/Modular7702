// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-empty-blocks */
/* solhint-disable no-inline-assembly */

import {IAccount} from "aa-0.8/interfaces/IAccount.sol";
import {IEntryPoint} from "aa-0.8/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "aa-0.8/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "aa-0.8/core/UserOperationLib.sol";
import {IERC7579Execution} from "oz-5.3/interfaces/draft-IERC7579.sol";
import {ERC7579Utils, Mode, CallType, ExecType} from "oz-5.3/account/utils/draft-ERC7579Utils.sol";

abstract contract BaseAccount is IAccount, IERC7579Execution {
    using UserOperationLib for PackedUserOperation;
    using ERC7579Utils for *;

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

    function _requireExecutorModule() public view virtual;

    function execute(bytes32 mode, bytes calldata executionCalldata) external payable onlyEntryPoint {
        _handleExecute(mode, executionCalldata);
    }

    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        _requireExecutorModule();
        return _handleExecute(mode, executionCalldata);
    }

    function _handleExecute(bytes32 mode, bytes calldata executionCalldata)
        internal
        returns (bytes[] memory returnData)
    {
        (CallType callType, ExecType execType,,) = Mode.wrap(mode).decodeMode();
        require(execType == ERC7579Utils.EXECTYPE_DEFAULT, ERC7579Utils.ERC7579UnsupportedExecType(execType));

        if (callType == ERC7579Utils.CALLTYPE_SINGLE && execType == ERC7579Utils.EXECTYPE_DEFAULT) {
            returnData = ERC7579Utils.execSingle(executionCalldata, ERC7579Utils.EXECTYPE_DEFAULT);
        } else if (callType == ERC7579Utils.CALLTYPE_BATCH && execType == ERC7579Utils.EXECTYPE_DEFAULT) {
            returnData = ERC7579Utils.execBatch(executionCalldata, ERC7579Utils.EXECTYPE_DEFAULT);
        } else {
            revert ERC7579Utils.ERC7579UnsupportedCallType(callType);
        }
    }
}
