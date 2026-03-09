// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Emitter {
    event ValueChanged(uint256 indexed newValue, uint256 value);
    event Four(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four);
    event Five(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, bytes five);
    event Six(uint256 indexed one, uint256 indexed two, uint256 indexed three, bytes four, uint256 five, bytes six);
    // event OrderFulfilled (bytes32 orderHash, index_topic_1 address offerer, index_topic_2 address zone, address recipient, tuple[] offer, tuple[] consideration)

    function emitValueChanged(uint256 value) public {
        emit ValueChanged(value, 5);
    }

    function emitFour(uint256 one, uint256 two, uint256 three, bytes memory four) public {
        emit Four(one, two, three, four);
    }
    function emitFive(uint256 one, uint256 two, uint256 three, bytes memory four, bytes memory five) public {
        emit Five(one, two, three, four, five);
    }
    
    function emitSix(uint256 one, uint256 two, uint256 three, bytes memory four, uint256 five, bytes memory six) public {
        emit Six(one, two, three, four, five, six);
    }
}