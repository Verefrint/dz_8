// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.26;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

error NonceNotAvailable();
error InvalidSignature();
error MessageExpired();

contract PasswordKeeper is Ownable {

    mapping(uint => bool) private nonces;

    string private password;

    constructor(string memory _passwordInstance) Ownable(msg.sender) {
        password = _passwordInstance;
    }

    function getPassword() external view onlyOwner returns(string memory) {
        return password;
    }

    function changePassword(string memory newPassword, uint nonce, bytes memory signature, uint timestamp) external {
        require(!nonces[nonce], NonceNotAvailable());
        require(timestamp >= block.timestamp, MessageExpired());

        nonces[nonce] = true;

        bytes32 message = withPrefix(keccak256(abi.encodePacked(
            msg.sender,
            Ownable.owner(),
            nonce,
            timestamp
        )));

        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

        require(
            ecrecover(message, v, r, s) == Ownable.owner(), InvalidSignature()
        );

        password = newPassword;
    }

    function splitSignature(bytes memory signature) private pure returns(uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65);

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return(v, r, s);
    }

    function withPrefix(bytes32 _hash) private pure returns(bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                _hash
            )
        );
    }
}