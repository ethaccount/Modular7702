// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PackedUserOperation} from "aa-0.8/interfaces/PackedUserOperation.sol";
import {IERC7579Module} from "oz-5.3/interfaces/draft-IERC7579.sol";

/* 
    Since PackedUserOperation from oz-5.3 is different from PackedUserOperation in aa-0.8, causing compilation errors,
    we don't use IERC7579Validator from oz-5.3 and instead consistently use PackedUserOperation from aa-0.8
*/

interface IERC7579Validator is IERC7579Module {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256);
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}
