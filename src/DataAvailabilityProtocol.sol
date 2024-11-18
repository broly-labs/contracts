// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IDataAvailabilityProtocol.sol";

contract DataAvailabilityProtocol is IDataAvailabilityProtocol {
    /**
     * @notice Struct which will store the blob verification data
     * @param blobHeader stores the header of the blob containing the relevant attributes of the blob
     * @param blobVerificationProof stores the relevant data needed to prove inclusion of the blob on EigenDA layer
     */
    struct BlobData {
        IEigenDAServiceManager.BlobHeader blobHeader;
        EigenDARollupUtils.BlobVerificationProof blobVerificationProof;
    }

    IEigenDAServiceManager public immutable EIGEN_DA_SERVICE_MANAGER;

    constructor(address _eigenDAServiceManager) {
        EIGEN_DA_SERVICE_MANAGER = IEigenDAServiceManager(_eigenDAServiceManager);
    }

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {
        EigenDARollupUtils.verifyBlob(blobHeader, EIGEN_DA_SERVICE_MANAGER, blobVerificationProof);
    }

    /**
     * @notice Decodes the data availaiblity message to the EigenDA blob data
     * @param data The encoded data availability message bytes
     */
    function decodeBlobData(bytes calldata data) public pure returns (BlobData memory blobData) {
        return abi.decode(data, (BlobData));
    }

    /**
     * @notice Verifies that the given blob verification proof has been signed by EigenDA operators and verified
     * on-chain to be to be available
     * @param data Byte array containing the abi-encoded EigenDA blob verification proof to be used for on-chain
     * verification with the EigenDAServiceManager
     */
    function verifyMessage(bytes calldata data) external view {
        BlobData memory blob = decodeBlobData(data);
        EigenDARollupUtils.verifyBlob(blob.blobHeader, EIGEN_DA_SERVICE_MANAGER, blob.blobVerificationProof);
    }
}
