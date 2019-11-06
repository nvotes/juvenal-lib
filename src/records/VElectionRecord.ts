import Ajv from 'ajv';

import { arithm, crypto, util } from "../../vendors/vjsc/vjsc-1.1.1";
import { ElectionRecord } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { schemas } from '../../vendors/electionguard-schema-0.85/json_schemas';

import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { 
    str_dec_to_hex,
    str_dec_to_modpgroup_element
} from '../crypto/utils';
import { baseline_parameters as modp_group } from '../crypto/baseline_params';
import { VCoefficientCommitmentsMatrixRecord, CoefficientCommitmentsMatrix } from './VCoefficientCommitmentsMatrixRecord';
import { create_joint_public_key } from '../crypto/elgamal_pub_keys';

/**
 * Using the election schemas, returns a correctly initialized Ajv schema
 * validator.
 */
function get_election_schema_validator(): Ajv.ValidateFunction 
{
    var ajv = new Ajv({allErrors: true});

    // add related schemas to the validator
    for (let [key, value] of Object.entries(schemas)) {
        ajv.addSchema(value, key);
    }

    var validate = ajv.compile(schemas['election_record.schema.json']);
    return validate;
}

/**
 * Helper function that converts the errors returned by Ajv.validate into a 
 * simple Error object.
 */
function convert_ajv_errors(
    errors: Ajv.ErrorObject[] | null | undefined
): Error {
    return new Error("\n" + (errors as Ajv.ErrorObject[])
        .map((error) => error.dataPath + " " + error.message)
        .reduce((total, message) => total +"\n" + message)
    );
}

/**
 * Election record implementation
 */
export class VElectionRecord implements VRecord {
    election: ElectionRecord;

    constructor(election_record: ElectionRecord) {
        this.election = election_record;
    } 

    modp_group(): arithm.ModPGroup {
        return modp_group;
    }
    
    verify(recorder: VRecorder): void {
        const context = ["election"];

        ///////////////// Non-Crypto verifications ///////////////////////////

        // validate the JSON schema
        var validate = get_election_schema_validator();
        var valid = validate(this.election);
        if (!valid) {
            (validate.errors as Ajv.ErrorObject[])
                .forEach((error) => 
                    recorder.record(
                        /*status=*/false,
                        context,
                        "ValidateJsonSchema",
                        error.dataPath + " " + error.message
                    )
                );
        } else {
            // record successful verification
            recorder.record(
                /*status=*/true,
                context,
                "ValidateJsonSchema",
                "Election record JSON schema should validate"
            )
        }

        // Verify some invariants related to the election that the json schema 
        // cannot not verify itself
        recorder.record(
            this.election.parameters.threshold <= this.election.parameters.num_trustees,
            context,
            "ThresholdTrustees",
            "The threshold of trustees that can decrypt the election should " +
            "be less than or equal to the number of trustees"
        );
        recorder.record(
            this.election.trustee_public_keys.length == this.election.parameters.num_trustees,
            context,
            "NumPubKeys",
            "The number of trustee public keys is equal to the defined " +
            "number of trustees"
        );
        // TODO: we should verify that the election.parameters.date is not 
        // in the future, as it has been already tallied. This can't be done 
        // currently because dates are not being correctly specified in the
        // schema.

        ///////////////// Crypto verifications ///////////////////////////////

        recorder.record(
            new arithm.LargeInteger(
                str_dec_to_hex(this.election.parameters.prime)
            ).equals(modp_group.modulus),
            context,
            "BaselineEncryptionModulus",
            "The election should use baseline encryption modulus"
        );

        recorder.record(
            new arithm.LargeInteger(
                str_dec_to_hex(this.election.parameters.generator)
            ).equals(modp_group.getg().value),
            context,
            "BaselineEncryptionGenerator",
            "The election should use baseline encryption group generator"
        );

        // Initialize verification public key records
        let coefficients = (
            (this.election.trustee_public_keys as unknown) as CoefficientCommitmentsMatrix
        );
        let v_coefficients: VCoefficientCommitmentsMatrixRecord[] = [];
        try {
            v_coefficients = coefficients
                .map((pub_key) =>
                    new VCoefficientCommitmentsMatrixRecord(this, pub_key)
                );
        } catch(err) {
            recorder.record(
                false,
                context,
                "CoefficientCommitmentsLoading",
                "Error loading trustees coefficient commitments: " + err.message
            );
        }

        // Verify that the public key of the election should be the combination
        // of the public keys of all the trustees
        let calculated_joint_pub_key = create_joint_public_key(
            v_coefficients.map(
                (pub_key) => pub_key.first_coefficient_el
            ),
            modp_group
        );

        let [err, joint_public_key] = str_dec_to_modpgroup_element(
            this.election.joint_public_key, 
            modp_group
        );

        if (err !== null) {
            recorder.record(
                false,
                context,
                "JointPublicKeyCalculation",
                "Error loading the public key of the election: " + err.message
            );
        } else {
            recorder.record(
                calculated_joint_pub_key.equals(joint_public_key as arithm.ModPGroupElement),
                context,
                "JointPublicKeyCalculation",
                "The public key of the election should be the combination of " +
                "the public keys of all the trustees"
            );
        }
    }
}
