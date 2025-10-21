// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PackedUserOperation} from "aa-0.8/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "aa-0.8/core/Helpers.sol";
import {IEntryPoint} from "aa-0.8/interfaces/IEntryPoint.sol";
import {IAccount} from "aa-0.8/interfaces/IAccount.sol";
import "oz-5.3/utils/introspection/IERC165.sol";
import "oz-5.3/interfaces/IERC1271.sol";
import "oz-5.3/token/ERC1155/utils/ERC1155Holder.sol";
import "oz-5.3/token/ERC721/utils/ERC721Holder.sol";
import "oz-5.3/utils/cryptography/ECDSA.sol";
import {ERC7579Utils, Mode, CallType, ExecType} from "oz-5.3/account/utils/draft-ERC7579Utils.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    IERC7579ModuleConfig,
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579Module
} from "oz-5.3/interfaces/draft-IERC7579.sol";

import {BaseAccount} from "./BaseAccount.sol";
import {IERC7579Validator} from "./interfaces/IERC7579Validator.sol";

contract SimpleModular7702Account is
    BaseAccount,
    IERC7579ModuleConfig,
    IERC7579AccountConfig,
    IERC165,
    IERC1271,
    ERC1155Holder,
    ERC721Holder
{
    using ERC7579Utils for *;

    error InvalidModule(address module);
    error ModuleAddressCanNotBeZero();
    error ModuleAlreadyInstalled(uint256 moduleTypeId, address module);
    error MismatchModuleTypeId();
    error ModuleNotInstalled(uint256 moduleTypeId, address module);

    // ================================================ Storage ================================================

    /// @dev cast index-erc7201 ethaccount.SimpleModular7702Account.0.0.1
    bytes32 private constant MAIN_STORAGE_SLOT = 0x2518c257f63affc9ee9dcce928ffdd39a87f98d73db3e9927c2e403aea47f400;

    struct MainStorage {
        mapping(address => bool) validators;
        mapping(address => bool) executors;
    }

    function _getMainStorage() private pure returns (MainStorage storage $) {
        assembly {
            $.slot := MAIN_STORAGE_SLOT
        }
    }

    // ================================================ Validation ================================================

    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256 validationData)
    {
        uint256 nonce = userOp.nonce;
        address validator;

        // userOp.nonce = 20 bytes validator address | 4 bytes empty | 8 bytes nonce
        assembly {
            validator := shr(96, nonce)
        }

        if (validator == address(0)) {
            validationData =
                _validateSignature(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
        } else {
            require(
                _isModuleInstalled(MODULE_TYPE_VALIDATOR, validator),
                ModuleNotInstalled(MODULE_TYPE_VALIDATOR, validator)
            );

            validationData = IERC7579Validator(validator).validateUserOp(userOp, userOpHash);
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        override
        returns (bytes4 magicValue)
    {
        address validator = address(bytes20(signature[0:20]));
        bytes memory actualSignature = signature[20:];

        if (validator == address(0)) {
            return _validateSignature(hash, actualSignature) ? this.isValidSignature.selector : bytes4(0xffffffff);
        } else {
            try IERC7579Validator(validator).isValidSignatureWithSender(msg.sender, hash, actualSignature) returns (
                bytes4 res
            ) {
                return res;
            } catch {
                return bytes4(0xffffffff);
            }
        }
    }

    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == address(this);
    }

    // ================================================ Execution ================================================

    function _requireExecutorModule() public view override {
        require(_getMainStorage().executors[msg.sender], InvalidModule(msg.sender));
    }

    // ================================================ Module Management ================================================

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        external
        override
        onlyEntryPointOrSelf
    {
        if (module == address(0)) revert ModuleAddressCanNotBeZero();

        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            require(_getMainStorage().validators[module], ModuleAlreadyInstalled(moduleTypeId, module));
            require(IERC7579Module(module).isModuleType(MODULE_TYPE_VALIDATOR), MismatchModuleTypeId());
            _getMainStorage().validators[module] = true;
            IERC7579Module(module).onInstall(initData);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            require(_getMainStorage().executors[module], ModuleAlreadyInstalled(moduleTypeId, module));
            require(IERC7579Module(module).isModuleType(MODULE_TYPE_EXECUTOR), MismatchModuleTypeId());
            _getMainStorage().executors[module] = true;
            IERC7579Module(module).onInstall(initData);
        }
        emit ModuleInstalled(moduleTypeId, module);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata) external onlyEntryPointOrSelf {
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

    // ================================================ View Functions ================================================

    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108); // v0.8
    }

    function accountId() external pure returns (string memory) {
        return "ethaccount.SimpleModular7702Account.0.0.1";
    }

    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return true;
        }
        return false;
    }

    function supportsExecutionMode(bytes32 mode) external pure returns (bool isSupported) {
        (CallType callType, ExecType execType,,) = Mode.wrap(mode).decodeMode();
        return (callType == ERC7579Utils.CALLTYPE_SINGLE || callType == ERC7579Utils.CALLTYPE_BATCH)
            && (execType == ERC7579Utils.EXECTYPE_DEFAULT);
    }

    function supportsInterface(bytes4 id) public pure override(ERC1155Holder, IERC165) returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IAccount).interfaceId || id == type(IERC1271).interfaceId
            || id == type(IERC1155Receiver).interfaceId || id == type(IERC721Receiver).interfaceId
            || id == type(IERC7579AccountConfig).interfaceId || id == type(IERC7579ModuleConfig).interfaceId
            || id == type(IERC7579Execution).interfaceId;
    }

    // accept incoming calls (with or without value), to mimic an EOA.
    fallback() external payable {}

    receive() external payable {}
}
