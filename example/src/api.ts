import { utils } from 'ethers'
import { MerkleTree } from 'merkletreejs'
import { createTree, getTree, getRoots, getProof } from 'lanyard'

const encode = utils.defaultAbiCoder.encode.bind(utils.defaultAbiCoder)
const encodePacked = utils.solidityPack

const makeMerkleTree = (leafData: string[]) =>
  new MerkleTree(leafData.map(utils.keccak256), utils.keccak256, {
    sortPairs: true,
  })

const checkRootEquality = (remote: string, local: string) => {
  if (remote !== local) {
    throw new Error(`Remote root ${remote} does not match local root ${local}`)
  }
}

const strArrEqual = (a: string[], b: string[]) =>
  a.length === b.length && a.every((v, i) => v === b[i])

const checkProofEquality = (remote: string[], local: string[]) => {
  if (!strArrEqual(remote, local)) {
    throw new Error(
      `Remote proof ${remote} does not match local proof ${local}`,
    )
  }
}

// basic merkle tree

const unhashedLeaves = [
  '0x0000000000000000000000000000000000000001',
  '0x0000000000000000000000000000000000000002',
  '0x0000000000000000000000000000000000000003',
  '0x0000000000000000000000000000000000000004',
  '0x0000000000000000000000000000000000000005',
]

const { merkleRoot: basicMerkleRoot } = await createTree({ unhashedLeaves })

console.log('basic merkle root', basicMerkleRoot)
checkRootEquality(basicMerkleRoot, makeMerkleTree(unhashedLeaves).getHexRoot())

const basicTree = await getTree(basicMerkleRoot)
console.log('basic leaf count', basicTree.leafCount)

console.log(basicMerkleRoot, unhashedLeaves[0])

const { proof: basicProof } = await getProof({
  merkleRoot: basicMerkleRoot,
  unhashedLeaf: unhashedLeaves[0],
})

console.log('proof', basicProof)
checkProofEquality(
  basicProof,
  makeMerkleTree(unhashedLeaves).getHexProof(
    utils.keccak256(unhashedLeaves[0]),
  ),
)

// non-address leaf data

const num2Addr = (num: number) =>
  utils.hexlify(utils.zeroPad(utils.hexlify(num), 20))

const leafData = []

for (let i = 1; i <= 5; i++) {
  leafData.push([num2Addr(i), 2, utils.parseEther('0.01').toString()])
}

// encoded data

const encodedLeafData = leafData.map((leafData) =>
  encode(['address', 'uint256', 'uint256'], leafData),
)

const { merkleRoot: encodedMerkleRoot } = await createTree({
  unhashedLeaves: encodedLeafData,
  leafTypeDescriptor: ['address', 'uint256', 'uint256'],
  packedEncoding: false,
})

console.log('encoded tree', encodedMerkleRoot)
checkRootEquality(
  encodedMerkleRoot,
  makeMerkleTree(encodedLeafData).getHexRoot(),
)

const { proof: encodedProof } = await getProof({
  merkleRoot: encodedMerkleRoot,
  unhashedLeaf: encodedLeafData[0],
})

console.log('encoded proof', encodedProof)
checkProofEquality(
  encodedProof,
  makeMerkleTree(encodedLeafData).getHexProof(
    utils.keccak256(encodedLeafData[0]),
  ),
)

// packed data

const encodedPackedLeafData = leafData.map((leafData) =>
  encodePacked(['address', 'uint256', 'uint256'], leafData),
)

const { merkleRoot: encodedPackedMerkleRoot } = await createTree({
  unhashedLeaves: encodedPackedLeafData,
  leafTypeDescriptor: ['address', 'uint256', 'uint256'],
  packedEncoding: true,
})

console.log('encoded packed tree', encodedPackedMerkleRoot)
checkRootEquality(
  encodedPackedMerkleRoot,
  makeMerkleTree(encodedPackedLeafData).getHexRoot(),
)

const { proof: encodedPackedProof } = await getProof({
  merkleRoot: encodedPackedMerkleRoot,
  unhashedLeaf: encodedPackedLeafData[0],
})

console.log('encoded packed proof', encodedPackedProof)
checkProofEquality(
  encodedPackedProof,
  makeMerkleTree(encodedPackedLeafData).getHexProof(
    utils.keccak256(encodedPackedLeafData[0]),
  ),
)

const { proof: encodedPackedProofByAddress } = await getProof({
  merkleRoot: encodedPackedMerkleRoot,
  address: num2Addr(1),
})

console.log(
  'encoded packed proof by indexed address',
  encodedPackedProofByAddress,
)
checkProofEquality(
  encodedPackedProofByAddress,
  makeMerkleTree(encodedPackedLeafData).getHexProof(
    utils.keccak256(encodedPackedLeafData[0]),
  ),
)

const root = await getRoots(encodedPackedProof)
console.log('roots from proof', root.roots[0])
checkRootEquality(root.roots[0], encodedPackedMerkleRoot)
