This was a smart-contract challenge that was part of the recent [SEETF 2022](https://ctftime.org/event/1543/) hosted by the [Social Engineering Experts](https://seetf.sg/seetf/). I played this together under [3_Blind_Mice](https://ctftime.org/team/190705), a random team made together with [@chuayupeng](https://github.com/chuayupeng) and [ethon](https://github.com/gnosis-agora) for pure fun and memes.

Like all the other smart-contract challenges in this CTF, a vulnerable contract was deployed onto [SEETF's very own private blockchain network](https://github.com/Social-Engineering-Experts/ETH-Guide).

Solving this challenge required knowing a concept in blockchain --> that `private` variables in a contract are still readable, and also understanding the difference between `tx.origin` and `msg.sender`.

We are given this `DuperSuperSafe.sol` contract as shown below:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DuperSuperSafeSafe {

  address private owner;
  mapping(uint => bytes32) private secret_passphrases;
  uint timestamp;

  constructor(bytes32 _secret_passphrase, bytes32 _secret_passphrase_2) payable {
    owner = msg.sender;
    timestamp = block.timestamp;
    secret_passphrases[0] = _secret_passphrase;
    secret_passphrases[1] = _secret_passphrase_2;
  }

  receive() external payable {}

  modifier restricted() {
    require(
      msg.sender == owner,
      "This function is restricted to the contract's owner"
    );
    _;
  }

  modifier passwordProtected(bytes32 _secret_passphrase, bytes32 _secret_passphrase_2, uint _timestamp) {
    require(keccak256(abi.encodePacked(secret_passphrases[0], secret_passphrases[1], timestamp)) == keccak256(abi.encodePacked(_secret_passphrase, _secret_passphrase_2, _timestamp)), "Wrong secret passphrase");
    _;
  }


  function changeOwner(address _newOwner) public {
    if (tx.origin != msg.sender) {
      owner = _newOwner;
    }
  }

  function changeSecretPassphrase(bytes32 _new_secret_passphrase, bytes32 _new_secret_passphrase_2, bytes32 _secret_passphrase, bytes32 _secret_passphrase_2, uint _timestamp) public restricted passwordProtected(_secret_passphrase, _secret_passphrase_2, _timestamp) {
    secret_passphrases[0] = _new_secret_passphrase;
    secret_passphrases[1] = _new_secret_passphrase_2;
    timestamp = block.timestamp;

  }

  function withdrawFunds(uint _amount, bytes32 _secret_passphrase, bytes32 _secret_passphrase_2, uint _timestamp) external payable restricted passwordProtected(_secret_passphrase, _secret_passphrase_2, _timestamp) {
    require(balanceOf(msg.sender) >= _amount, "Not enough funds");
    payable(address(msg.sender)).transfer(_amount);
  }

  function balanceOf(address _addr) public view returns (uint balance) {
    return address(_addr).balance;
  }

  function isSolved() public view returns (bool) {
    return balanceOf(address(this)) == 0;
  }

}
```

Based on the source code itself, we can learn a couple of things
- We can see in the `constructor()` that when the contract is first created, the 2 secret passphrases are passed in to the constructor and the `timestamp` is set to `block.timestamp`, which is essentially the timestamp of the block that holds the transaction of the contract creation.
- There is a `withdrawFunds()` function which has 2 modifiers
  - `restricted()` which requires `msg.sender` to be the owner
  - `passwordProtected(_secret_passphrase, _secret_passphrase_2, _timestamp)` which requires inputting the correct 2 secret passphrases and then being compared against `secret_passphrases[0]` and `secret_passphrases[1]`, along with the timestamp.
- There is also a `changeOwner()` function which takes in the new owner's address. The only requirement to call this function is that `tx.origin` matches `msg.sender`.
- We solve the problem when we drain all the funds in the contract itself as seen in `isSolved()`.
  - We can see the available balance of the contract with `web3.eth.getBalance()` as shown below:

## Exploit 1 - Making tx.origin != msg.sender
We first go to understand what's the difference between `tx.origin` and `msg.sender`. I believe this [article](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-5-calling-other-contracts-visibility-state-access/topic/tx-origin-and-msg-sender/) explains things really well but in short, `tx.origin` refers to the account that makes the function call and `msg.sender` refers to the immediate last instance to a function call. 

To exploit this, what we really need to do is essentially, craft a scenario such that `tx.origin` is not the same as `msg.sender`. We can simply do this by creating a contract and making the contract call the `changeOwner()` function of the deployed `DuperSuperSafe.sol` contract. The contract we created in this case would be our `msg.sender`, and while that happens, when we use this contract to call `changeOwner()`, we ourselves become `tx.origin` :)

This is what we need to do:

```solidity
contract Attack {
    DuperSuperSafeSafe dsss;

    constructor(address payable _addr) {
        dsss = DuperSuperSafeSafe(_addr);
    }

    function pwn(address _newOwner) public {
        dsss.changeOwner(_newOwner);
    }
}
```

Now let's compile and deploy this contract. We can make use of the `web3.eth.getStorageAt()` function to read the value of `owner` (more will be explained in the next section).

