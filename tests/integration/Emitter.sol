// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Emitter {
    event ValueChanged(uint256 indexed newValue, uint256 value);
    event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, uint256 four);

    function emitValueChanged(uint256 value) public {
        emit ValueChanged(value, 5);
    }

    function emitFour(uint256 one, uint256 two, uint256 three, uint256 four) public {
        emit Four(one, two, three, four);
    }
}