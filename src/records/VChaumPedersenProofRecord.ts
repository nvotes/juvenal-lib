import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { ChaumPedersenProof } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { SchnorrProof as CryptoSchnorrProof } from '../crypto/SchnorrProof';
import { strDecToByteArray, strDecToByteTree } from '../crypto/utils';
