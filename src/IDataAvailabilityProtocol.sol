// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {EigenDARollupUtils} from "eigenda/contracts/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "eigenda/contracts/interfaces/IEigenDAServiceManager.sol";


interface IDataAvailabilityProtocol {
    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view;

    function verifyMessage(
        bytes calldata dataAvailabilityMessage
    ) external view;
}
