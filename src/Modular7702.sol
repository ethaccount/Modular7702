// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountERC7579, IERC7579AccountConfig} from "oz-5.4/account/extensions/draft-AccountERC7579.sol";
// import {ERC7821} from "oz-5.4/account/extensions/draft-ERC7821.sol";

contract Modular7702 is AccountERC7579 {
     /// @inheritdoc IERC7579AccountConfig
    function accountId() public pure override returns (string memory) {
        // vendorname.accountname.semver
        return "ethaccount.Modular7702.v0.0.1";
    }
}
