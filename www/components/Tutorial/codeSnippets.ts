export const installDependenciesCode = `
npm install merkletreejs ethers
`.trim()

const addressPlaceholderComments = [
  'your addresses will be filled in here automatically when',
  'you click the "Copy" button on the top of this code block',
]
  .map((comment) => `  // ${comment}`)
  .join('\n')

export const merkleSetupCode = (addresses: string[]) =>
  `
import { MerkleTree } from 'merkletreejs';
import { utils } from 'ethers';

const addresses: string[] = [
${
  addresses.length > 0
    ? addresses.map((a) => `  '${a}',`).join('\n')
    : addressPlaceholderComments
}
];

const tree = new MerkleTree(
  addresses.map(utils.keccak256),
  utils.keccak256,
  { sortPairs: true },
);

console.log('the Merkle root is:', tree.getRoot().toString('hex'));

export function getMerkleRoot() {
  return tree.getRoot().toString('hex');
}

export function getMerkleProof(address: string) {
  const hashedAddress = utils.keccak256(address);
  return tree.getHexProof(hashedAddress);
}
`.trim()

export const passMerkleProofCode = `
import { getMerkleProof } from './merkle.ts';

// right before minting, get the Merkle proof for the current wallet
// const walletAddress = ...
const merkleProof = getMerkleProof(walletAddress);

// pass this to your contract
await myContract.mintAllowList(merkleProof);
`.trim()

export const nftMerkleProofCode = `
import {MerkleProof} from "openzeppelin/utils/cryptography/MerkleProof.sol";

contract NFTContract is ERC721 {
  bytes32 public merkleRoot;

  constructor(bytes32 _merkleRoot) {
    merkleRoot = _merkleRoot;
  }

  // Check the Merkle proof using this function
  function allowListed(address _wallet, bytes32[] calldata _proof)
      public
      view
      returns (bool)
    {
      return
          MerkleProof.verify(
              _proof,
              merkleRoot,
              keccak256(abi.encodePacked(_wallet))
          );
    }
  
  function mintAllowList(uint256 _tokenId, bytes32[] calldata _proof) external {
    require(allowListed(msg.sender, _proof), "You are not on the allowlist");
    _mint(msg.sender, _tokenId);
  }
}
`.trim()
