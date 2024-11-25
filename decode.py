# The raw data arrays
proof_commitment = [40, 80, 224, 180, 101, 2, 80, 11, 193, 23, 230, 120, 207, 151, 74, 165, 37, 203, 195, 152, 235, 85, 55, 193, 44, 240, 5, 0, 204, 35, 143, 21]
pub_input_commitment = [0] * 32
proving_system_aux_data = [93, 140, 104, 91, 143, 194, 241, 219, 102, 139, 105, 30, 85, 211, 154, 51, 56, 28, 176, 11, 248, 46, 186, 83, 65, 197, 31, 62, 107, 232, 114, 217]
proof_generator_addr = [118, 117, 205, 244, 85, 164, 245, 85, 73, 138, 49, 48, 214, 44, 189, 144, 183, 184, 117, 183]
batch_merkle_root = [141, 235, 141, 212, 165, 4, 201, 108, 202, 204, 86, 223, 179, 194, 73, 131, 49, 7, 90, 208, 157, 101, 124, 254, 248, 244, 40, 62, 52, 249, 41, 108]
merkle_path = [
    [88, 213, 198, 188, 189, 155, 6, 98, 50, 69, 136, 143, 9, 49, 153, 229, 5, 46, 220, 47, 250, 225, 20, 191, 175, 146, 128, 122, 147, 187, 117, 12],
    [183, 62, 111, 65, 57, 145, 238, 56, 48, 42, 164, 239, 58, 60, 82, 40, 50, 55, 67, 246, 159, 90, 215, 117, 90, 1, 149, 218, 52, 31, 36, 185],
    [167, 117, 60, 177, 111, 12, 176, 21, 143, 26, 112, 215, 60, 70, 212, 134, 168, 89, 136, 108, 238, 212, 75, 14, 224, 208, 105, 251, 187, 92, 230, 254],
    [184, 9, 194, 42, 217, 205, 242, 175, 157, 159, 207, 212, 146, 193, 175, 114, 40, 19, 144, 3, 202, 26, 225, 90, 219, 230, 11, 98, 141, 102, 60, 164],
    [57, 36, 173, 50, 57, 194, 204, 144, 73, 3, 87, 166, 131, 36, 120, 187, 33, 246, 43, 193, 140, 26, 220, 78, 146, 160, 160, 67, 146, 81, 22, 247]
]

# Convert arrays to hex strings
def array_to_hex32(arr):
    return "0x" + "".join([format(x, '02x') for x in arr])

def array_to_hex20(arr):
    return "0x" + "".join([format(x, '02x') for x in arr])

# Convert merkle path to concatenated bytes
def merkle_path_to_bytes(paths):
    return "0x" + "".join(["".join([format(x, '02x') for x in path]) for path in paths])

# Format the data for Solidity
print("Format for Solidity VerificationData struct:")
print("[")
print(f"  {array_to_hex32(proof_commitment)},              // proofCommitment")
print(f"  {array_to_hex32(pub_input_commitment)},          // pubInputCommitment")
print(f"  {array_to_hex32(proving_system_aux_data)},       // provingSystemAuxDataCommitment")
print(f"  {array_to_hex20(proof_generator_addr)},          // proofGeneratorAddr")
print(f"  {array_to_hex32(batch_merkle_root)},            // batchMerkleRoot")
print(f"  {merkle_path_to_bytes(merkle_path)},            // merkleProof")
print(f"  0,                                              // verificationDataBatchIndex")
print(f"  \"0x0000000000000000000000000000000000000000\"   // batcherPaymentService (replace with actual address)")
print("]")

print("\nIndividual values for reference:")
print(f"proofCommitment: {array_to_hex32(proof_commitment)}")
print(f"pubInputCommitment: {array_to_hex32(pub_input_commitment)}")
print(f"provingSystemAuxDataCommitment: {array_to_hex32(proving_system_aux_data)}")
print(f"proofGeneratorAddr: {array_to_hex20(proof_generator_addr)}")
print(f"batchMerkleRoot: {array_to_hex32(batch_merkle_root)}")
print(f"merkleProof: {merkle_path_to_bytes(merkle_path)}")