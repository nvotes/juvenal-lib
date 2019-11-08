import { util, eio, arithm } from '../../vendors/vjsc/vjsc-1.1.1';
import { bindExpression } from '@babel/types';

/**
 * Receives a string of a number in decimal base and returns it in 
 * hexadecimal base, also as a string.
 * 
 * @param dec_li_str A decimal large integer number either as a string
 *                   or as a native typescript number.
 */
export function str_dec_to_hex(dec_li_str: string | number): string {
    return BigInt(dec_li_str).toString(16);
}

/**
 * Receives a string of a number in decimal base and returns it as
 * a byte array.
 * @param dec_li_str A decimal large integer number either as a string
 *                   or as a native typescript number.
 */
export function str_dec_to_byte_array(
    dec_li_str: string | number
): Uint8Array {
    return util.hexToByteArray(BigInt(dec_li_str).toString(16));
}

/**
 * Converts a number as a string into a byte tree of the correct size.
 * 
 * @param dec_li_str A decimal large integer number either as a string
 *                   or as a native typescript number.
 * @param tree_size Required size in bytes of the returned bytree
 */
export function str_dec_to_byte_tree(
    dec_li_str: string | number,
    tree_size: number
): [Error | null, eio.ByteTree | null] {
    let hex = str_dec_to_hex(dec_li_str); 

    // First make it even so that byte length calculations work
    if (hex.length % 2 == 1) {
        hex = "0" + hex;
    }

    if (tree_size > hex.length / 2) {
        [new Error("Number is too big for encoding"), null];
    }

    // We don't mind having number bigger than tree_size, so that's
    // why we use Math.Max here.
    // The padding size is otherwise the number of extra zeros we
    // require to have the appropiate number of bytes
    let padding_size = Math.max(0, tree_size - hex.length / 2);
    for (var i = 0; i < padding_size; i++) {
        hex = "00" + hex;
    }

    return [null, eio.ByteTree.asByteTree(util.hexToByteArray(hex))];
}

/**
 * Converts a number as a string into a ModPGroupElement.
 * 
 * @param dec_li_str A decimal large integer number either as a string
 *                   or as a native typescript number.
 * @param modp_group The multiplicative modular group to be used.
 */
export function str_dec_to_modpgroup_element(
    dec_li_str: string | number,
    modp_group: arithm.ModPGroup
): [Error | null, arithm.ModPGroupElement | null] 
{
    // First convert it to byte tree, dealing with errors if any
    let [err, byte_tree] = str_dec_to_byte_tree(
        dec_li_str,
        modp_group.modulusByteLength
    );
    if (err) { 
        return [err, null]
    }
    
    // Then convert it to a group element, dealing with errors if any
    let element: arithm.ModPGroupElement;
    try {
        element = modp_group.toElement(byte_tree as eio.ByteTree);
    } catch(err) {
        return [err, null];
    }

    // as arithm.ModPGroupElement.toElement() doesn't do this,
    // we manually ensure that the element is a quadratic 
    // residue i.e. it's a member of Z^r_p (Gq).
    if (element.value.legendre(modp_group.modulus) !== 1) {
        return [new Error("The element is not a quadratic residue"), null];
    }

    return [null, element];
}

/**
 * Returns the string without any spaces
 * @param s input string
 */
export function remove_spaces(s: string): string {
    return s.replace(/[ \t\n]/g, "");
}
