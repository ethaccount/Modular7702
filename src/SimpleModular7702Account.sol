// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "oz-5.1/utils/introspection/IERC165.sol";
import "oz-5.1/interfaces/IERC1271.sol";
import "oz-5.1/token/ERC1155/utils/ERC1155Holder.sol";
import "oz-5.1/token/ERC721/utils/ERC721Holder.sol";
import "oz-5.1/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "aa-0.8/core/Helpers.sol";
import "aa-0.8/core/BaseAccount.sol";
import "aa-0.8/interfaces/IEntryPoint.sol";
import "nexus-1.2/interfaces/IERC7579Account.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "nexus-1.2/types/Constants.sol";
import "nexus-1.2/lib/ModeLib.sol";
import "nexus-1.2/base/ExecutionHelper.sol";
import "nexus-1.2/interfaces/base/IModuleManager.sol";
import "nexus-1.2/interfaces/modules/IValidator.sol";
import "nexus-1.2/interfaces/modules/IExecutor.sol";

interface ISimpleModular7702Account {
    struct MainStorage {
        mapping(address => bool) validators;
        mapping(address => bool) executors;
    }

    error NotFromEntryPoint();
    error NotFromEntryPointOrSelf();
}

/**
 * Modified from eth-infinitism v0.8 Simple7702Account.sol
 * A minimal account to be used with EIP-7702, ERC-4337, and ERC-7579
 */
contract SimpleModular7702Account is
    BaseAccount,
    IERC165,
    IERC1271,
    ERC1155Holder,
    ERC721Holder,
    ISimpleModular7702Account,
    IERC7579Account,
    ExecutionHelper,
    IModuleManager
{
    using ModeLib for ExecutionMode;

    /// @dev cast index-erc7201 ethaccount.SimpleModular7702Account.0.0.1
    bytes32 private constant MAIN_STORAGE_SLOT = 0x2518c257f63affc9ee9dcce928ffdd39a87f98d73db3e9927c2e403aea47f400;

    function _getMainStorage() private pure returns (MainStorage storage $) {
        assembly {
            $.slot := MAIN_STORAGE_SLOT
        }
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint()), NotFromEntryPoint());
        _;
    }

    modifier onlyEntryPointOrSelf() {
        require(msg.sender == address(entryPoint()) || msg.sender == address(this), NotFromEntryPointOrSelf());
        _;
    }

    modifier onlyExecutorModule() virtual {
        require(_getMainStorage().executors[msg.sender], InvalidModule(msg.sender));
        _;
    }

    // address of entryPoint v0.8
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    }

    function accountId() external pure virtual returns (string memory) {
        return "ethaccount.SimpleModular7702Account.0.0.1";
    }

    function supportsModule(uint256 moduleTypeId) external view virtual returns (bool) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return true;
        }
        return false;
    }

    function supportsExecutionMode(ExecutionMode mode) external view virtual returns (bool isSupported) {
        (CallType callType, ExecType execType) = mode.decodeBasic();

        // Return true if both the call type and execution type are supported.
        return (callType == CALLTYPE_SINGLE || callType == CALLTYPE_BATCH || callType == CALLTYPE_DELEGATECALL)
            && (execType == EXECTYPE_DEFAULT || execType == EXECTYPE_TRY);
    }

    function execute(ExecutionMode mode, bytes calldata executionCalldata) external payable onlyEntryPoint {
        (CallType callType, ExecType execType) = mode.decodeBasic();
        if (callType == CALLTYPE_SINGLE) {
            _handleSingleExecution(executionCalldata, execType);
        } else if (callType == CALLTYPE_BATCH) {
            _handleBatchExecution(executionCalldata, execType);
        } else if (callType == CALLTYPE_DELEGATECALL) {
            _handleDelegateCallExecution(executionCalldata, execType);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    function executeFromExecutor(ExecutionMode mode, bytes calldata executionCalldata)
        external
        payable
        onlyExecutorModule
        returns (bytes[] memory returnData)
    {
        (CallType callType, ExecType execType) = mode.decodeBasic();
        // check if calltype is batch or single or delegate call
        if (callType == CALLTYPE_SINGLE) {
            returnData = _handleSingleExecutionAndReturnData(executionCalldata, execType);
        } else if (callType == CALLTYPE_BATCH) {
            returnData = _handleBatchExecutionAndReturnData(executionCalldata, execType);
        } else if (callType == CALLTYPE_DELEGATECALL) {
            returnData = _handleDelegateCallExecutionAndReturnData(executionCalldata, execType);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        external
        payable
        virtual
        override
        onlyEntryPointOrSelf
    {
        if (module == address(0)) revert ModuleAddressCanNotBeZero();

        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            require(_getMainStorage().validators[module], ModuleAlreadyInstalled(moduleTypeId, module));
            require(IValidator(module).isModuleType(MODULE_TYPE_VALIDATOR), MismatchModuleTypeId());
            _getMainStorage().validators[module] = true;
            IValidator(module).onInstall(initData);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            require(_getMainStorage().executors[module], ModuleAlreadyInstalled(moduleTypeId, module));
            require(IExecutor(module).isModuleType(MODULE_TYPE_EXECUTOR), MismatchModuleTypeId());
            _getMainStorage().executors[module] = true;
            IExecutor(module).onInstall(initData);
        }
        emit ModuleInstalled(moduleTypeId, module);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata)
        external
        payable
        onlyEntryPointOrSelf
    {
        require(_isModuleInstalled(moduleTypeId, module), ModuleNotInstalled(moduleTypeId, module));

        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            require(_getMainStorage().validators[module], ModuleNotInstalled(moduleTypeId, module));
            _getMainStorage().validators[module] = false;
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            require(_getMainStorage().executors[module], ModuleNotInstalled(moduleTypeId, module));
            _getMainStorage().executors[module] = false;
        }
        emit ModuleUninstalled(moduleTypeId, module);
    }

    function _isModuleInstalled(uint256 moduleTypeId, address module) internal view returns (bool) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            return _getMainStorage().validators[module];
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return _getMainStorage().executors[module];
        }
        return false;
    }

    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata) external view returns (bool) {
        return _isModuleInstalled(moduleTypeId, module);
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        return _checkSignature(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        public
        view
        override(IERC1271, IERC7579Account)
        returns (bytes4 magicValue)
    {
        return _checkSignature(hash, signature) ? this.isValidSignature.selector : bytes4(0xffffffff);
    }

    function _checkSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
    }

    function _requireForExecute() internal view virtual override {
        require(msg.sender == address(this) || msg.sender == address(entryPoint()), "not from self or EntryPoint");
    }

    function supportsInterface(bytes4 id) public pure override(ERC1155Holder, IERC165) returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IAccount).interfaceId || id == type(IERC1271).interfaceId
            || id == type(IERC1155Receiver).interfaceId || id == type(IERC721Receiver).interfaceId;
    }

    // accept incoming calls (with or without value), to mimic an EOA.
    fallback() external payable {}

    receive() external payable {}
}
