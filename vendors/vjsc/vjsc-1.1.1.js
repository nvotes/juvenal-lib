// Copyright 2008-2019 Douglas Wikstrom
//
// This file is part of Verificatum JavaScript Cryptographic library
// (VJSC).
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// ######################################################################
// ############## Javascript Verificatum Crypto Libary ##################
// ######################################################################

/**
* @description
* This library provides the cryptographic routines needed by an
* electronic voting client implemented in Javascript. It is documented
* in detail and considerable time has been invested in organizing the
* the code.
*
* <p>
*
* Although this library is fast, the goal is not to be as fast as
* possible, but to be fast enough and as clean and well documented as
* possible. M4 macros are used for both purposes.
*
* <p>
*
* The library is compiled from multiple files using M4 into a single
* properly formatted and indented file that encapsulates all functionality
* that should not be readily accessible. Users should not add any variables
* or functions to the namespaces.
*
* <p>
*
* This is not a general purpose library for cryptographic
* software. Please read the warnings below.
*
* <p>
*
* This library consists of a stack of the following modules:
*
* <ul>
*
* <li> {@link verificatum.arithm.li} is a raw multi-precision integer
*      arithmetic module. This is essentially optimized in only two
*      ways; memory allocation must be handled manually, and the
*      inner-most so-called "muladd" loop is optimized. Apart from this,
*      it is a relatively straightforward implementation of school book
*      arithmetic. References are provided for all non-trivial algorithms.
*
* <li> {@link verificatum.arithm.sli} provides signed multi-precision
*      integer arithmetic. This is a thin layer on top of
*      {@link verificatum.arithm.li} along with a few extra basic routines
*      are are easier to implement with signed arithmetic than without,
*      e.g., the extended binary greatest common divisor algorithm.
*
* <li> {@link verificatum.arithm.LargeInteger} provides automatic memory
*      allocation on top of {@link verificatum.arithm.li} and
*      {@link verificatum.arithm.sli}.
*
* <li> {@link verificatum.arithm.PGroup} provides abstract classes that
*      capture groups of prime order.
*
* <li> {@link verificatum.arithm.ModPGroup} provides prime order
*      subgroups modulo primes. This is a wrapper of
*      {@link verificatum.arithm.LargeInteger} using modular arithmetic
*      that provides additional utility routines.
*
* <li> {@link verificatum.arithm.ec} provides a raw implementation of
*      elliptic curves over prime order fields of Weierstrass form using
*      a variant of Jacobi coordinates. This uses the standard formulas,
*      but on top of {@link verificatum.arithm.sli}
*      (not {@link verificatum.arithm.LargeInteger}).
*
* <li> {@link verificatum.arithm.ECqPGroup} provides elliptic curve
*      groups over prime order fields of Weierstrass form using a
*      variant of Jacobi coordinates. In particular the standard curves
*      of this form. This is a wrapper of {@link verificatum.arithm.ec}
*      that provides automatic memory allocation and additional utility
*      routines.
*
* <li> {@link verificatum.arithm.PField} implements a prime order field
*      that may be thought of as the "exponents of a group". This is a
*      wrapper of {@link verificatum.arithm.LargeInteger}, where computations
*      take place modulo the order of the group. It also provides additional
*      utility routines.
*
* <li> {@link verificatum.arithm.PPGroup} implements a product group
*      that combines multiple groups into one to simplify computations
*      over multiple group elements. The resulting group elements
*      are basically glorified lists with routines that iterate over the
*      individual elements. It generalizes both the arithmetic and
*      utility functions to product groups.
*
* <li> {@link verificatum.arithm.PPRing} implements the product ring of
*      a product group. We may think of this as the "ring of
*      exponents". Similarly to product groups its elements are
*      glorified lists of field elements along with arithmetic and
*      utility routines that iterate over these elements.
*
* </ul>
*
* A notable pattern used in the code is using static variables in
* functions, where a variable is static if it survives function
* invocations. This is implemented using encapsulation with immediate
* functions. Static variables are re-sized as needed, but for our
* application this rarely happens, so effectively we have automatic
* light-weight memory allocation.
*
* <p>
*
* Some classes can be optionally included in the library. See
* <code>BUILDING.md</code> and <code>Makefile</code> for more
* information. Testing if a class is included is done using
* <code>typeof</code>, e.g., the following is a
* boolean that is true if and only if the class `ECqPGroup` was
* included in the build.
*
* <p>
*
* <code>typeof verificatum.arithm.ECqPGroup !== "undefined"</code>
*
* <p>
*
* The function <code>verificatum.util.ofType</code> is robust as
* long as the second parameter is either a string literal or a type.
* To keep things consistent, we only use
* <code>typedef variable === "undefined"</code> when checking for
* <code>undefined</code> parameters to functions.
*
* <p>
*
* <b>WARNING! Please read the following instructions carefully.
* Failure to do so may result in a completely insecure installation.</b>
*
* <p>
*
* You should NOT use this library unless you have verified the following:
*
* <ol>
*
* <li> Run all tests. JavaScript is a language with a heterogeneous set
*      of available interpreters/engines. We have done our best to only
*      use the most standard features, but we can not exclude the
*      possibility that there are issues on any particular platform,
*      since there are simply too many and they are constantly evolving.
*
* <li> Verify that the random source accessible from
*      <code>verificatum.crypto.RandomDevice</code> is secure.
*      A number of natural approaches are possible if this is not the
*      case. We avoid all of these until we have a clear reason, since
*      they bring additional complexity and potential incompatibilities
*      and security issues in themselves.
*
* </ol>
*
* <p>
*
* <b>WARNING! Please read the following instructions carefully.
* Failure to do so may result in a completely insecure installation.</b>
*
* <p>
*
* This library <b>does not protect against side channel
* attacks</b>. Thus, this is <b>not</b> a general purpose cryptographic
* library, but it is secure in electronic voting clients because of two
* reasons:
*
* <ol>
*
* <li> The system is currently only used for encryption. Thus, random
*      encryption exponents of the El Gamal cryptosystem are only used
*      once. This effectively curtails any cache or timing attacks due
*      to the lack of statistics.
*
* <li> A human being determines when encryption takes place. Thus, the
*      adversary can not influence when an encryption takes place with
*      sufficient granularity to execute repeated attacks.
*
* </ol>
*
* This should be compared with, e.g., a TLS server that handles repeated
* requests from a potential adversary using a fixed secret key.
*
* <p>
*
* Our software handles special curve points correctly and all inputs are
* verified to belong to the right domain before processing. This turns
* out to be particularly important for the mix-nets that process the
* ciphertexts formed using this library.
*
* <p>
*
* However, we naturally welcome the inclusion of non-NIST curves that
* are more resistant against side channel attacks. For more information
* we recommend, e.g., Daniel J. Bernstein and Tanja Lange.
* <em>SafeCurves: choosing safe curves for elliptic-curve cryptography</em>,
* (accessed 1 December 2014).
*
* <p>
*
* <b>WARNING! Please read the following instructions carefully.
* Failure to do so may result in a completely insecure installation.</b>
*
* <p>
*
* This library <b>does not on its own protect against attacks against
* the browser or the operating system</b>. A short and non-exhaustive
* list of threats includes:
*
* <ol>
*
* <li> Virus that corrupts the client as a whole.
*
* <li> Cross-scripting attacks.
*
* <li> Functional, memory, resource leakage between plugins or interpreters
*      of the browser.
*
* <li> Weak source of randomness provided by the browser. This includes
*      attempts to provide randomness by observing mouse movements (less
*      relevant in a world with touch screens), or accessing external
*      sites with built-in crypto libraries to harvest randomness.
*
* </ol>
*
* It is impossible to fully protect a client against such attacks. We
* can only reduce the risk in different ways.
*
* <p>
*
* However, electronic voting systems typically provide mechanisms at the
* cryptographic protocol level to allow the voter or auditors to verify
* that the right vote is encrypted.
*
* <p>
*
* Thus, these risks are "only" relevant for privacy if the rest of the
* system is implemented properly.
* @namespace verificatum
*/

var verificatum = (function () {

/**
* @description Utility classes and functions.
* @namespace util
* @memberof verificatum
*/
var util = (function () {


// ######################################################################
// ################### Utility Functions ################################
// ######################################################################

/**
* @description Returns the epoch in milliseconds.
* @return Epoch in milliseconds.
* @function time_ms
* @memberof verificatum.util
*/
function time_ms() {
return (new Date()).getTime();
};

/**
* @description Returns the epoch in seconds.
* @return Epoch in seconds.
* @function time
* @memberof verificatum.util
*/
function time() {
return Math.floor(time_ms() / 1000);
};

/**
* @description Tests if an object is of a given type.
*
* <p>
*
* ASSUMPTIONS: type is a string literal and not an instance of String.
* @param obj Object to determine type of. (Here we can use either a
* string literal or a String instance if obj is a string to patch the
* intellectually challenged way JavaScript handles these.)
* @param type Type of object.
* @return True or false depending on if the object is of the given
* type or not.
* @function ofType
* @memberof verificatum.util
*/
var ofType = function (obj, type) {

// typeof s for a string literal s is always "string".
if (typeof type === "string") {
if (type === "array") {
return Array.isArray(obj);
} else if (type === "string") {
return typeof obj === type || obj instanceof String;
} else {
return typeof obj === type;
}
} else {
return obj.constructor === type;
}
};

/**
* @description Creates a list filled with the same value.
* @param value Value to be repeated.
* @param width Number of repetitions.
* @return List containing the value.
* @function full
* @memberof verificatum.util
*/
var fill = function (value, width) {
var a = [];
for (var i = 0; i < width; i++) {
a[i] = value;
}
return a;
};

/**
* @description Creates a list filled with the same value or the value
* itself if a single repetition is requested.
* @param value Value to be repeated.
* @param width Number of repetitions.
* @return List containing the value or the value itself if width == 1.
* @function full
* @memberof verificatum.util
*/
var full = function (value, width) {
if (typeof width === "undefined" || width === 1) {
return value;
} else {
return fill(value, width);
}
};

/**
* @description Changes the wordsize of an array of words.
* @param words Array of words.
* @param orig_wordsize Original bitsize of words (at most 32).
* @param new_wordsize Bitsize of output words (at most 32).
* @return Representation of the input array of bits with new
* wordsize.
* @function change_wordsize
* @memberof verificatum.util
*/
var change_wordsize = function (words, orig_wordsize, new_wordsize) {

var mask_all = 0xFFFFFFFF >>> 32 - new_wordsize;

// Array with new wordsize holding result.
var new_words = [];
new_words[0] = 0;

// Encodes bit position in words.
var j = 0;
var jb = 0;

// Encodes bit position in new_words.
var i = 0;
var ib = 0;

while (j < words.length) {

// Insert as many bits as possible from words[j] into new_words[i].
new_words[i] |= words[j] >>> jb << ib & mask_all;

// Number of inserted bits.
var inserted_bits = Math.min(orig_wordsize - jb, new_wordsize - ib);

// Determine if we have filled new_words[i] and if so, then move on
// to the beginning of the next word.
ib = ib + inserted_bits;
if (ib === new_wordsize) {
i++;
ib = 0;
new_words[i] = 0;
}

// Determine the number of remaining unused bits of words[j] and
// if none are left, then move on to the beginning of the next
// word.
jb = jb + inserted_bits;
if (jb === orig_wordsize) {
j++;
jb = 0;
}
}
return new_words;
};

var digits = "0123456789abcdef";

var hex = function (b) {
return digits[b >> 4 & 0xF] + digits[b & 0xF];
};

/**
* @description Converts an ASCII string to a byte array.
* @param ascii ASCII string.
* @return Corresponding byte array.
* @function asciiToByteArray
* @memberof verificatum.util
*/
var asciiToByteArray = function (ascii) {
var bytes = [];
for (var i = 0; i < ascii.length; i++) {
bytes.push(ascii.charCodeAt(i));
}
return bytes;
};

/**
* @description Converts byte array to ASCII string.
* @param bytes Input bytes.
* @return ASCII string corresponding to the input.
* @function byteArrayToAscii
* @memberof verificatum.util
*/
var byteArrayToAscii = function (bytes) {
var ascii = "";
for (var i = 0; i < bytes.length; i++) {
ascii += String.fromCharCode(bytes[i]);
}
return ascii;
};

/**
* @description Converts a byte array to its hexadecimal encoding.
* @param array Input byte array.
* @return Hexadecimal representation of this array.
* @function byteArrayToHex
* @memberof verificatum.util
*/
var byteArrayToHex = function (array) {
var hexString = "";
for (var i = 0; i < array.length; i++) {
hexString += hex(array[i]);
}
return hexString;
};

/**
* @description Converts a hexadecimal encoding of a byte array to the
* byte array.
* @param hex Hexadecimal encoding of byte array.
* @return Byte array corresponding to the input.
* @function hexToByteArray
* @memberof verificatum.util
*/
var hexToByteArray = function (hex) {

// Correct hex strings of uneven length.
if (hex.length % 2 === 1) {
hex = "0" + hex;
}

// Convert bytes.
var res = [];
var i = 0;
hex.replace(/(..)/g,
function (hex) {
res[i++] = parseInt(hex, 16);
});
return res;
};

/**
* @description Returns true or false depending on if the two input
* arrays hold identical elements or not.
* @param x Array of elements.
* @param y Array of elements.
* @return Value of boolean equality predicate for arrays.
* @function equalsArray
* @memberof verificatum.util
*/
var equalsArray = function (x, y) {

if (x.length !== y.length) {
return false;
}
for (var i = 0; i < x.length; i++) {
if (x[i] !== y[i]) {
return false;
}
}
return true;
};

/**
* @description Generates random array of the given length and
* wordsize.
* @param len Number of nominal bits in random output.
* @param wordsize Number of bits in each word.
* @param randomSource Source of randomness.
* @return Array of randomly generated words.
* @function randomArray
* @memberof verificatum.util
*/
var randomArray = function (len, wordsize, randomSource) {

var no_bytes = Math.floor((len * wordsize + 7) / 8);
var bytes = randomSource.getBytes(no_bytes);

var no_msbits = wordsize % 8;
if (no_msbits !== 0) {
bytes[no_bytes - 1] &= 0xFF >>> 8 - no_msbits;
}

if (wordsize === 8) {
return bytes;
} else {
return change_wordsize(bytes, 8, wordsize);
}
};

/**
* @description Reads a 32-bit integer in little-endian byte order
* from the given byte array.
* @param bytes Source of bytes.
* @param index Offset for reading.
* @function readUint32FromByteArray
* @memberof verificatum.util
*/
var readUint32FromByteArray = function (bytes, index) {
if (typeof index === "undefined") {
index = 0;
}
var value = 0;
for (var i = index; i < index + 4; i++) {
value <<= 8;
value |= bytes[i];
}
return value >>> 0;
};

/**
* @description Writes a 32-bit integer in little-endian byte order.
* @param destination Destination of result.
* @param value Value to write.
* @param index Offset for writing.
* @function setUint32ToByteArray
* @memberof verificatum.util
*/
var setUint32ToByteArray = function (destination, value, index) {

for (var i = index + 3; i >= index; i--) {
destination[i] = value & 0xFF;
value >>= 8;
}
};

/**
* @description Reads a 16-bit integer in little-endian byte order
* from the given byte array.
* @param bytes Source of bytes.
* @param index Offset for reading.
* @function readUint16FromByteArray
* @memberof verificatum.util
*/
var readUint16FromByteArray = function (bytes, index) {
if (typeof index === "undefined") {
index = 0;
}
var value = 0;
for (var i = index; i < index + 2; i++) {
value <<= 8;
value |= bytes[i];
}
return value >>> 0;
};

/**
* @description Writes a 16-bit integer in little-endian byte order.
* @param destination Destination of result.
* @param value Value to write.
* @param index Offset for writing.
* @function setUint16ToByteArray
* @memberof verificatum.util
*/
var setUint16ToByteArray = function (destination, value, index) {

for (var i = index + 1; i >= index; i--) {
destination[i] = value & 0xFF;
value >>= 8;
}
};

return {

"time_ms": time_ms,
"time": time,
"ofType": ofType,
"fill": fill,
"full": full,
"change_wordsize": change_wordsize,
"asciiToByteArray": asciiToByteArray,
"byteArrayToAscii": byteArrayToAscii,
"byteArrayToHex": byteArrayToHex,
"hexToByteArray": hexToByteArray,
"equalsArray": equalsArray,
"randomArray": randomArray,
"readUint32FromByteArray": readUint32FromByteArray,
"setUint32ToByteArray": setUint32ToByteArray,
"readUint16FromByteArray": readUint16FromByteArray,
"setUint16ToByteArray": setUint16ToByteArray
};
})();


// ######################################################################
// ################### eio ##############################################
// ######################################################################

/**
* @description Extended input and output routines.
*
* @namespace eio
* @memberof verificatum
*/
var eio = (function () {


// ##################################################################
// ############### ByteTree #########################################
// ##################################################################

/**
* @description Class for representing ordered trees of byte arrays. A
* byte tree is represented as an array of bytes as follows.
*
* <ul>
*
* <li> A leaf holding a sequence of bytes B of length l is converted
*      into a byte array T|L|B, where "|" denotes concatenation, T is
*      a single byte equal to 1 indicating that this is a leaf, and L
*      is a 32-bit signed integer representation of l.
*
* <li> A node holding children c_0,...,c_{l-1} is converted into a
*      byte array T|L|C_0|...|C_{l-1}, where T is a single byte equal
*      to 0 indicating that this is a node, L is a 32-bit unsigned
*      integer representation of l and C_i is the representation of
*      c_i as a byte array.
*
* </ul>
*
* @param value Data needed to construct a byte tree. This can
* be: (1) an array of other byte trees that becomes siblings in the
* new instance, (2) a raw byte array in which case the resulting
* instance becomes a leaf, or (3) a hexadecimal string representing a
* byte tree. The hexadecimal string may contain an ASCII encoded
* prefix ending with "::", in which case it is discarded.
* @return Byte tree containing the input data.
* @class
* @memberof verificatum.eio
*/
function ByteTree(value) {

if (verificatum.util.ofType(value, "array")) {
if (typeof value[0] === "number") {
this.type = ByteTree.LEAF;
this.value = value;
} else {
this.type = ByteTree.NODE;
this.value = value;
}

} else if (verificatum.util.ofType(value, "string")) {

// Strip comment if present.
var start = value.indexOf("::");
if (start > 0) {
value = value.slice(start + 2);
}

// Recover byte tree from hex string.
var array = util.hexToByteArray(value);
var bt = ByteTree.readByteTreeFromByteArray(array);
this.type = bt.type;
this.value = bt.value;

} else {
throw Error("Unexpected type of input!");
}
};

// These are internal constants.
ByteTree.LEAF = 1;
ByteTree.NODE = 0;

/**
* @description Recovers a byte tree from its representation as a byte
* array from the given source. If the second parameter is given, then
* reading starts at this position and a pair is returned. If no
* second parameter is given, then the byte tree is simply returned.
* @param source Array holding a representation of a byte tree.
* @param index Position in the array where reading starts.
* @return Recovered byte tree.
* @method
*/
ByteTree.readByteTreeFromByteArray = function (source, index) {
var outputPair = true;
if (typeof index === "undefined") {
index = 0;
outputPair = false;
}
var pair = ByteTree.readByteTreeFromByteArrayInner(source, index);

if (outputPair) {
return pair;
} else {
return pair[0];
}
};

// This is an internal function.
ByteTree.readByteTreeFromByteArrayInner = function (source, index) {

var origIndex = index;

// Read type of byte tree.
var type = source[index];
if (type !== ByteTree.LEAF && type !== ByteTree.NODE) {
throw Error("Unknown type! (" + type + ")");
}
index++;

// Read number of bytes/children.
var length = verificatum.util.readUint32FromByteArray(source, index);
if (length <= 0) {
throw Error("Non-positive length! (" + length + ")");
}
index += 4;

var byteTree;

if (type === ByteTree.LEAF) {

if (index + length <= source.length) {

var data = source.slice(index, index + length);
index += length;
byteTree = new ByteTree(data);

} else {
throw new Error("Unable to read data for leaf, missing bytes! (" +
"index = " + index + ", length = " + length + ")");
}

} else {

var children = [];
for (var i = 0; i < length; i++) {
var pair = ByteTree.readByteTreeFromByteArrayInner(source, index);
children.push(pair[0]);
index += pair[1];
}
byteTree = new ByteTree(children);
}
return [byteTree, index - origIndex];
};

/**
* @description Guarantees that the input is a byte tree.
* @param value Byte tree or a byte array.
* @return Input value if it is a byte tree and a leaf byte tree based
* on the byte array otherwise.
* @method
*/
ByteTree.asByteTree = function (value) {
if (util.ofType(value, eio.ByteTree)) {
return value;
} else {
return new eio.ByteTree(value);
}
};

/**
* @description Indicates if this byte tree is a leaf or not.
* @return True or false depending on if this byte tree is a leaf or not.
* @method
*/
ByteTree.prototype.isLeaf = function () {
return this.type === ByteTree.LEAF;
};

/**
* @description Computes the total number of bytes needed to represent
* this byte tree as a byte array.
* @return Number of bytes needed to store a byte array representation
* of this byte tree.
* @method
*/
ByteTree.prototype.size = function () {
if (this.type === ByteTree.LEAF) {
return 1 + 4 + this.value.length;
} else if (this.type === ByteTree.NODE) {
var size = 1 + 4;
for (var i = 0; i < this.value.length; i++) {
size += this.value[i].size();
}
return size;
} else {
throw Error("Unknown type! (" + this.type + ")");
}
};

/**
* @description Writes a byte tree representation of this byte tree to
* the destination starting at the given index.
* @param destination Destination of written bytes.
* @param index Index of starting position.
* @return Number of bytes written.
* @method
*/
ByteTree.prototype.setToByteArray = function (destination, index) {
if (this.type === ByteTree.LEAF) {

destination[index] = ByteTree.LEAF;
index++;

verificatum.util.setUint32ToByteArray(destination,
this.value.length,
index);
index += 4;

var i = index;
var j = 0;
while (j < this.value.length) {
destination[i] = this.value[j];
i++;
j++;
}


return 1 + 4 + this.value.length;

} else {

var origIndex = index;


destination[index] = ByteTree.NODE;
index++;

verificatum.util.setUint32ToByteArray(destination,
this.value.length,
index);
index += 4;

for (var k = 0; k < this.value.length; k++) {
index += this.value[k].setToByteArray(destination, index);
}
return index - origIndex;
}
};

// drb
ByteTree.prototype.setToByteArrayRaw = function (destination, index) {
if (this.type === ByteTree.LEAF) {

var i = index;
var j = 0;
while (j < this.value.length) {
destination[i] = this.value[j];
i++;
j++;
}

return this.value.length;

} else {

var origIndex = index;

for (var k = 0; k < this.value.length; k++) {
index += this.value[k].setToByteArrayRaw(destination, index);
}
return index - origIndex;
}
};

ByteTree.prototype.toByteArrayRaw = function () {
var array = [];
this.setToByteArrayRaw(array, 0);
return array;
};
// drb

/**
* @description Generates a representation of this byte tree as a byte
* array.
* @return Representation of this byte tree as a byte array.
* @method
*/
ByteTree.prototype.toByteArray = function () {
var array = [];
this.setToByteArray(array, 0);
return array;
};

/**
* @description Generates hexadecimal representation of this byte
* tree.
* @return Hexadecimal representation of this byte tree.
* @method
*/
ByteTree.prototype.toHexString = function () {
var ba = this.toByteArray();
return verificatum.util.byteArrayToHex(ba);
};

// This is an internal function.
/* istanbul ignore next */
ByteTree.prototype.toPrettyStringInner = function (indent) {

if (this.type === ByteTree.LEAF) {

return indent +
"\"" + verificatum.util.byteArrayToHex(this.value) + "\"";

} else if (this.type === ByteTree.NODE) {

var s = indent + "[\n";
for (var i = 0; i < this.value.length; i++) {
if (i > 0) {
s += ",\n";
}
s += this.value[i].toPrettyString(indent + "    ");
}
s += "\n" + indent + "]";
return s;

} else {
throw Error("Unknown type! (" + this.type + ")");
}
};

/* istanbul ignore next */
/**
* @description Generates representation as a nested JSON list with
* the leaves as hexadecimal string representations of the data in
* leaves. This is meant for debugging.
* @return Pretty representation of this byte tree.
* @method
*/
ByteTree.prototype.toPrettyString = function () {
return this.toPrettyStringInner("");
};

return {
"ByteTree": ByteTree
};
})();


// ######################################################################
// ################### arithm ###########################################
// ######################################################################

/**
* @description Arithmetic objects and routines. This is a port of the
* Verificatum Mix-Net (VMN) which introduces abstractions that
* facilitates the implementation of generalized cryptographic
* primitives and protocols.
*
* <p>
*
* More precisely, the implementations of generalized primitives and
* protocols is syntactically identical to their original versions,
* e.g., the complex code found in other libraries for handling lists
* of ciphertexts is completely eliminated. This gives less error
* prone code, a smaller code base, and the code is easier to verify.
*
* @namespace arithm
* @memberof verificatum
*/
var arithm = (function () {


// ######################################################################
// ################### ArithmObject #####################################
// ######################################################################

/* istanbul ignore next */
/**
* @description Arithmetic object.
* @abstract
* @class
* @memberof verificatum.crypto
*/
function ArithmObject() {
};
ArithmObject.prototype = Object.create(Object.prototype);
ArithmObject.prototype.constructor = ArithmObject;

ArithmObject.prototype.getName = function () {
var regex = /function\s?([^(]{1,})\(/;
var results = regex.exec(this.constructor.toString());
return results && results.length > 1 ? results[1] : "";
};


// ######################################################################
// ################### li ###############################################
// ######################################################################

/**
* @description Utility classes and functions.
*
* <p>
*
* Provides the core large integer arithmetic routines needed to
* implement multiplicative groups and elliptic curve groups over
* prime order fields. No additional functionality is provided.
* Although the main goal of this module is to be well-documented and
* clearly structured with proper encapsulation and without hidden
* assumptions, this is quite hard in a few routines.
*
* <p>
*
* WARNING! This module must be used with care due to the assumptions
* made by routines on inputs, but these assumptions are stated
* explicitly for each function, so the code is easy to follow.
*
* <p>
*
* Integers are represented as arrays of numbers constrained to
* WORDSIZE bits, where WORDSIZE is any even number between 4 and 30
* and there are hardcoded constants derived from this when the script
* is generated, so do not attempt to change the wordsize in the
* generated code. These wordsizes are natural since JavaScript only
* allows bit operations on 32-bit signed integers. To see this, note
* that although we can do arithmetic on floating point numbers, e.g.,
* by setting WORDSIZE = 24 we could do multiplications directly, it
* is expensive to recover parts of the result. Bit operations on
* 32-bit integers are provided in Javascript, but they are
* implemented on top of the native "number" datatype, i.e., numbers
* are cast to 32-bit signed integers, the bit operation is applied,
* and the result is cast back to a "number".
*
* <p>
*
* Using small wordsizes exposes certain types of arithmetic bugs, so
* providing this is not merely for educational purposes, it is also
* to lower the risk of structural bugs.
*
* <p>
*
* Functions are only implemented for unsigned integers and when
* called from external functions they assume that any result
* parameter is of a given length. All arithmetic functions guarantee
* that any leading unused words are set to zero.
*
* <p>
*
* A "limb" is an element of an array that may or may not store any
* single-precision integer. A word is a limb containing data, which
* may be zero if there are limbs at higher indices holding
* data. Thus, the number of limbs is the length of an array and the
* number of words is the index of the most significant word in the
* array plus one.
*
* <p>
*
* The workhorse routine is muladd_loop() which is generated for a
* given fixed wordsize. This routine determines the speed of
* multiplication and squaring. To a large extent it also determines
* the speed of division, but here div3by2() also plays an important
* role. These routines are generated from M4 macro code to allow
* using hard coded wordsize dependent constants for increased
* speed. The square_naive() routine also contains some generated
* code.
*
* <p>
*
* JavaScript is inherently difficult to optimize, since the
* JavaScript engines are moving targets, but it seems that the
* built-in arrays in Javascript are faster than the new typed arrays
* if they are handled properly. A first version of the library was
* based on Uint32Array for which, e.g., allocation of a fixed-size
* array is slower than a builtin array.
*
* <p>
*
* One notable observation is that it sometimes makes sense to inform
* the interpreter that a JavaScript "number" / float is really a
* 32-bit integer by saying, e.g., (x | 0) even if we are guaranteed
* that x is a 32-bit integer. This is important when accessing
* elements from arrays and it seems to prevent the interpreter from
* converting to and from floats.
*
* <p>
*
* We avoid dynamic memory allocation almost entirely by keeping
* scratch space as static variables of the functions. This is
* implemented using immediate function evaluation in JavaScript, but
* it is encapsulated to reduce complexity, i.e., calling functions
* remain unaware of this. This approach works well in our
* applications, since higher level routines work with integers of
* fixed bit length;
*
* <p>
*
* <a href="http://cacr.uwaterloo.ca/hac">Handbook of Cryptography
* (HAC), Alfred J. Menezes, Paul C. van Oorschot and Scott
* A. Vanstone</a> gives a straightforward introduction to the basic
* algorithms used and we try to follow their notation for easy
* reference. Division exploits the techniques of <a
* href="https://gmplib.org/~tege/division-paper.pdf">Improved
* division by invariant integers, Niels Moller and Torbjorn Granlund
* (MG)</a>. This is needed to implement div3by2() efficiently.
*
* <p>
*
* <table style="text-align: left;">
* <tr><th>Reference        </th><th> Operation</th><th> Comment</th></tr>
* <tr><td>HAC 14.7.        </td><td> Addition</td><td></td></tr>
* <tr><td>HAC 14.9.        </td><td> Subtraction</td><td></td></tr>
* <tr><td>HAC 14.12.       </td><td> Multiplication</td><td> Uses Karatsuba.</td></tr>
* <tr><td>HAC 14.16.       </td><td> Squaring</td><td> Uses Karatsuba.</td></tr>
* <tr><td>HAC 14.20 and MG.</td><td> Division.</td><td> Uses reciprocals for invariant moduli.</td></tr>
* <tr><td>HAC 14.83.       </td><td> Modular exponentiation</td><td> Left-to-right k-ary.</td></tr>
* </table>
*
* @namespace li
* @memberof verificatum.arithm
*/
var li = (function () {

// ################### Constants ########################################

// Wordsize.
var WORDSIZE = 28;

// Size threshold for using Karatsuba in multiplication.
var KARATSUBA_MUL_THRESHOLD = 24;

// Size threshold for using Karatsuba in squaring.
var KARATSUBA_SQR_THRESHOLD = 35;

// Threshold for relative difference in size for using Karatsuba in
// multiplication.
var KARATSUBA_RELATIVE = 0.8;

/**
* @description Sets x = 0.
* @param x Array to modify.
* @function setzero
* @memberof verificatum.arithm.li
*/
var setzero = function (x) {
for (var i = 0; i < x.length; i++) {
x[i] = 0;
}
};

/**
* @description Sets w = x and truncates or pads with zeros as needed
* depending on the number of limbs in w. The x parameter can be an
* array or a "number" < 2^28.
* @param w Array or "number" holding result.
* @param x Array holding value.
* @function set
* @memberof verificatum.arithm.li
*/
var set = function (w, x) {
if (typeof x === "number") {
setzero(w);
w[0] = x;
} else {
var i = 0;
while (i < Math.min(w.length, x.length)) {
w[i] = x[i];
i++;
}
while (i < w.length) {
w[i] = 0;
i++;
}
}
};

/**
* @description Allocates new array of the given length where all
* elements are zero.
* @param len Length of array.
* @return Array of the given length where all elements are zero.
* @function newarray
* @memberof verificatum.arithm.li
*/
var newarray = function (len) {
var x = [];
x.length = len;
setzero(x);
return x;
};

/**
* @description Returns a copy of the given array.
* @param x Original array.
* @param len Maximal length of copy.
* @return Copy of original array.
* @function copyarray
* @memberof verificatum.arithm.li
*/
var copyarray = function (x, len) {
if (typeof len === "undefined") {
len = 0;
}
var w = newarray(Math.max(x.length, len));
set(w, x);
return w;
};

/**
* @description Resizes the array to the given number of limbs,
* either by truncating or by adding leading zero words.
* @param x Original array.
* @param len New length.
* @function resize
* @memberof verificatum.arithm.li
*/
var resize = function (x, len) {
var xlen = x.length;
x.length = len;
if (len > xlen) {
for (var i = xlen; i < len; i++) {
x[i] = 0;
}
}
};

/**
* @description Truncates the input to the shortest possible array
* that represents the same absolute value in two's complement, i.e.,
* there is always a leading zero bit.
* @param x Array to truncate.
* @param mask_top Mask for a given wordsize with only most
* significant bit set.
* @function normalize
* @memberof verificatum.arithm.li
*/
var normalize = function (x, mask_top) {

if (typeof mask_top === "undefined") {
mask_top = 0x8000000;
}

var l = x.length - 1;

// There may be zeros to truncate.
if (x[l] === 0) {

// Find index of most significant non-zero word.
while (l > 0 && x[l] === 0) {
l--;
}

// If most significant bit of this word is set, then we keep a
// leading zero word.
if ((x[l] & mask_top) !== 0) {
l++;
}
x.length = l + 1;

// We need to add a zero word to turn it into a positive integer
// in two's complement.
} else if ((x[l] & mask_top) !== 0) {

x.length++;
x[x.length - 1] = 0;
}
};

/**
* @description Sets x = 1.
* @param x Array to modify.
* @function setone
* @memberof verificatum.arithm.li
*/
var setone = function (x) {
setzero(x);
x[0] = 1;
};

/**
* @description Returns the index of the most significant bit in x.
* @param x Array containing bit.
* @return An index i such that 0 <= i < x.length * 28.
* @function msbit
* @memberof verificatum.arithm.li
*/
var msbit = function (x) {

for (var i = x.length - 1; i >= 0; i--) {

// Find index of most significant word.
if (x[i] !== 0) {

// Find index of most significant bit within the most
// significant word.
var msbit = (i + 1) * 28 - 1;

for (var mask = 0x8000000; mask !== 0; mask >>>= 1) {

if ((x[i] & mask) === 0) {
msbit--;
} else {
return msbit;
}
}
}
}
return 0;
};

/**
* @description Returns the lowest index of a set bit in the input or
* zero if the input is zero.
* @param Array containing bit.
* @return An index i such that 0 <= i < x.length * 28.
* @function lsbit
* @memberof verificatum.arithm.li
*/
var lsbit = function (x) {
var i = 0;
while (i < x.length && x[i] === 0) {
i++;
}

if (i === x.length) {

return 0;

} else {

var j = 0;
while ((x[i] >>> j & 0x1) === 0) {
j++;
}

return i * 28 + j;
}
};

/**
* @description Returns the array index of the most significant word.
* @param x Array containing word.
* @return An index i such that 0 <= i < x.length.
* @function msword
* @memberof verificatum.arithm.li
*/
var msword = function (x) {
for (var i = x.length - 1; i > 0; i--) {
if (x[i] !== 0) {
return i;
}
}
return 0;
};

/**
* @description Returns 1 or 0 depending on if the given bit is set or
* not. Accessing a bit outside the number of limbs returns zero.
* @param x Array containing bit.
* @param index Index of bit.
* @return Bit as a "number" at the given position.
* @function getbit
* @memberof verificatum.arithm.li
*/
var getbit = function (x, index) {
var wordIndex = Math.floor(index / 28);
var bitIndex = index % 28;

if (wordIndex >= x.length) {
return 0;
}

if ((x[wordIndex] & 1 << bitIndex) === 0) {
return 0;
} else {
return 1;
}
};

/**
* @description Checks if the input represents the zero integer.
* @param x Array to inspect.
* @return True or false depending on if x represents zero or not.
* @function iszero
* @memberof verificatum.arithm.li
*/
var iszero = function (x) {
for (var i = 0; i < x.length; i++) {
if (x[i] !== 0) {
return false;
}
}
return true;
};

/**
* @description Returns -1, 0, or 1 depending on if x < y, x == y, or
* x > y.
*
* <p>
*
* ASSUMES: x and y are positive.
*
* @param x Left array.
* @param x Right array.
* @return Sign of comparison relation.
* @function cmp
* @memberof verificatum.arithm.li
*/
var cmp = function (x, y) {

// Make sure that x has at least as many words as y does, and
// remember if we swapped them to correct the sign at the end.
var sign = 1;
if (x.length < y.length) {
var t = x;
x = y;
y = t;
sign = -1;
}

var i = x.length - 1;

while (i >= y.length) {
if (x[i] === 0) {
i--;
} else {
return sign;
}
}
while (i >= 0) {
if (x[i] > y[i]) {
return sign;
} else if (x[i] < y[i]) {
return -sign;
}
i--;
}
return 0;
};

/**
* @description Shifts the given number of bits within the array,
* i.e., the allocated space is not expanded.
*
* <p>
*
* ASSUMES: offset >= 0.
*
* @param x Array to be shifted.
* @param offset Number of bit positions to shift.
* @function shiftleft
* @memberof verificatum.arithm.li
*/
var shiftleft = function (x, offset) {

// No shifting.
if (offset === 0) {
return;
}

// Too much shifting.
if (offset >= x.length * 28) {
setzero(x);
return;
}

// Left shift words.
var wordOffset = Math.floor(offset / 28);
if (wordOffset > 0) {

var j = x.length - 1;
while (j >= wordOffset) {
x[j] = x[j - wordOffset];
j--;
}
while (j >= 0) {
x[j] = 0;
j--;
}
}

// Left shift bits within words.
var bitOffset = offset % 28;
var negBitOffset = 28 - bitOffset;

if (bitOffset !== 0) {
for (var i = x.length - 1; i > 0; i--) {
var left = x[i] << bitOffset & 0xfffffff;
var right = x[i - 1] >>> negBitOffset;
x[i] = left | right;
}
x[0] = x[0] << bitOffset & 0xfffffff;
}
};

/**
* @description Shifts the given number of bits to the right within
* the allocated space, i.e., the space is not reduced.
*
* <p>
*
* ASSUMES: offset >= 0.
*
* @param x Array to be shifted.
* @param offset Number of bit positions to shift.
* @function shiftright
* @memberof verificatum.arithm.li
*/
var shiftright = function (x, offset) {

// No shifting.
if (offset === 0) {
return;
}

// Too much shifting.
if (offset >= x.length * 28) {
setzero(x);
return;
}

// Right shift words.
var wordOffset = Math.floor(offset / 28);
if (wordOffset > 0) {

var j = 0;
while (j < x.length - wordOffset) {
x[j] = x[j + wordOffset];
j++;
}
while (j < x.length) {
x[j] = 0;
j++;
}
}

// Right shift bits within words.
var bitOffset = offset % 28;
var negBitOffset = 28 - bitOffset;

if (bitOffset !== 0) {
for (var i = 0; i < x.length - 1; i++) {
var left = x[i] >>> bitOffset;
var right = x[i + 1] << negBitOffset & 0xfffffff;
x[i] = left | right;
}
x[x.length - 1] = x[x.length - 1] >>> bitOffset;
}
};

/**
* @description Sets w = x + y.
*
* <p>
*
* ASSUMES: x and y are positive and have B and B' bits and w can
* store (B + B' + 1) bits. A natural choice in general is to let w
* have (L + L' + 1) limbs if x and y have L and L' limbs, but the
* number of limbs can be arbitrary.
*
* <p>
*
* References: HAC 14.7.
*
* @param w Array holding the result.
* @param x Left term.
* @param y Right term.
* @function add
* @memberof verificatum.arithm.li
*/
var add = function (w, x, y) {
var tmp;
var c = 0;

// Make sure that x is at least as long as y.
if (x.length < y.length) {
var t = x;
x = y;
y = t;
}

// Add words of x and y with carry.
var i = 0;
var len = Math.min(w.length, y.length);
while (i < len) {
tmp = x[i] + y[i] + c;

w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}

// Add x and carry.
len = Math.min(w.length, x.length);
while (i < len) {
tmp = x[i] + c;

w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}

// Set carry and clear the rest.
if (i < w.length) {
w[i] = c;
i++;
}
while (i < w.length) {
w[i] = 0;
i++;
}
};

/* jshint -W126 */ /* Ignore singleGroups. */
/* eslint-disable no-extra-parens */
/**
* @description Sets w to the negative of x in two's complement
* representation using L * 28 bits, where L is the number of
* limbs in w.
*
* <p>
*
* ASSUMES: w has at least as many limbs as x.
*
* @param w Array holding the result.
* @param x Integer.
* @function neg
* @memberof verificatum.arithm.li
*/
var neg = function (w, x) {
var i;
var c;
var tmp;

c = 1;
i = 0;
while (i < x.length) {
tmp = (x[i] ^ 0xfffffff) + c;
w[i] = tmp & 0xfffffff;
c = (tmp >> 28) & 0xfffffff;
i++;
}
while (i < w.length) {
tmp = 0xfffffff + c;
w[i] = tmp & 0xfffffff;
c = (tmp >> 28) & 0xfffffff;
i++;
}
};
/* jshint +W126 */ /* Stop ignoring singleGroups. */
/* eslint-enable no-extra-parens */

/**
* @description Sets w = x - y if x >= y and otherwise it simply
* propagates -1, i.e., 0xfffffff, through the remaining words of
* w.
*
* <p>
*
* ASSUMES: for normal use x >= y, and x and y have B and B' bits and
* w can store B bits. A natural choice is to use L >= L' limbs for x
* and y respectively and L limbs for w, but the number of limbs can
* be arbitrary.
*
* <p>
*
* References: HAC 14.9.
*
* @param w Array holding the result.
* @param x Left term.
* @param y Right term.
* @return Finally carry.
* @function sub
* @memberof verificatum.arithm.li
*/
var sub = function (w, x, y) {
var tmp;
var c = 0;

// Subtract words of x and y with carry.
var len = Math.min(w.length, x.length, y.length);

var i = 0;
while (i < len) {
tmp = x[i] - y[i] + c;
w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}

// Propagate carry along with one of x and y.
if (x.length > y.length) {
len = Math.min(w.length, x.length);
while (i < len) {
tmp = x[i] + c;
w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}
} else {
len = Math.min(w.length, y.length);
while (i < len) {
tmp = -y[i] + c;
w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}
}

// Propagate carry.
while (i < w.length) {
w[i] = c & 0xfffffff;
c = tmp >> 28;
i++;
}
return c;
};

/* jshint -W126 */ /* Ignore singleGroups. */
/* eslint-disable no-extra-parens */
/* eslint-disable space-in-parens */
/* eslint-disable semi-spacing */
/**
* @description Specialized implementation of muladd_loop() for
* 28-bit words. This is essentially a naive
* double-precision multiplication computation done in a loop. This
* code is quite sensitive to replacing the constants with variables,
* which explains why it is generated from source with macros. Using
* two's complement for temporary values this can be used as a
* "mulsub_loop" as well.
*
* <p>
*
* Computes (pseudo-code) that due to limited precision and 32-bit
* bound bit operations does not work in JavaScript:
*
* <pre>
* for (var j = start; j < end; j++) {
*     tmp = x[j] * Y + w[i + j] + c;
*     w[i + j] = tmp & 0xfffffff;
*     c = tmp >>> 28;
* }
* return c;
* </pre>
*
* <p>
*
* Note that if Y < 2^(28 + 1), then the output carry c is
* only guaranteed to be smaller than 2^(28 + 1), which does
* not fit into a word.
*
* <p>
*
* ASSUMES: Y < 2^(28 + 1).
*
* @param w Array holding additive terms as input and the output.
* @param x Array to be scaled.
* @param start Start index into x.
* @param end End index into x.
* @param Y Scalar.
* @param i Index into w.
* @param c Input carry.
* @return Finally carry.
* @function muladd_loop
* @memberof verificatum.arithm.li
*/
var muladd_loop = function (w, x, start, end, Y, i, c) {

// Temporary variables in muladd.
var hx;
var lx;
var cross;

// Extract upper and lower halves of Y.
var hy = (Y >>> 14);
var ly = (Y & 0x3fff);

// This implies:
// hy < 2^(14 + 1)
// ly < 2^14

// The invariant of the loop is c < 2^(28 + 1).
for (var j = start; j < end; j++) {

// Extract upper and lower halves of x.
hx = (x[j] >>> 14);
lx = (x[j] & 0x3fff);

// This implies:
// hx < 2^14
// lx < 2^14

// Compute the sum of the cross terms.
cross = (hx * ly + lx * hy) | 0;

// This implies:
// cross < 2^(28 + 2)

// Partial computation from which the lower word can be
// extracted.
lx = (((w[j + i] | 0) + lx * ly +
((cross & 0x3fff) << 14)) | 0) + c;

// This implies: so we can safely use bit operator on lx.
// lx < 2^(28 + 2)

// Complete the computation of the higher bits.
c = ((lx >>> 28) + hx * hy +
(cross >>> 14) ) | 0;

// Extract the lower word of x * y.
w[j + i] = lx & 0xfffffff;
}

// This is a (28 + 1)-bit word when Y is.
return c;
};

/**
* @description Sets w = x * y, where w has two limbs and x and y are
* words. This is specialized similarly to muladd_loop and generated
* using the same macro.
*
* @param w Destination long.
* @param x Single word factor.
* @param y Single word factor.
*
* @function word_mul
* @memberof verificatum.arithm.li
*/
var word_mul = function (w, x, y) {
var hx;
var lx;
var cross;
var hy;
var ly;

// Clear the result, since we are muladding.
w[0] = 0;
w[1] = 0;

// Extract upper and lower halves of y.
hy = (y >>> 14);
ly = (y & 0x3fff);

// Extract upper and lower halves of x.
hx = (x >>> 14);
lx = (x & 0x3fff);

// This implies:
// hx < 2^14
// lx < 2^14

// Compute the sum of the cross terms.
cross = (hx * ly + lx * hy) | 0;

// This implies:
// cross < 2^(28 + 2)

// Partial computation from which the lower word can be
// extracted.
lx = (((w[0] | 0) + lx * ly +
((cross & 0x3fff) << 14)) | 0) + w[1];

// This implies: so we can safely use bit operator on lx.
// lx < 2^(28 + 2)

// Complete the computation of the higher bits.
w[1] = ((lx >>> 28) + hx * hy +
(cross >>> 14) ) | 0;

// Extract the lower word of x * y.
w[0] = lx & 0xfffffff;
};
/* jshint +W126 */ /* Stop ignoring singleGroups */
/* eslint-enable no-extra-parens */
/* eslint-enable space-in-parens */
/* eslint-enable semi-spacing */

/* jshint -W126 */ /* Ignore singleGroups */
/* eslint-disable no-extra-parens */
/**
* @description Sets w = x * x.
*
* <p>
*
* ASSUMES: x is non-negative with L and L' limbs respectively, and
* that w has at least L + L' limbs.
*
* <p>
*
* References: HAC 14.16.
*
* @param w Array holding the result.
* @param x Factor.
* @function square_naive
* @memberof verificatum.arithm.li
*/
var square_naive = function (w, x) {
var n = msword(x) + 1;
var c;
var sc = 0;

setzero(w);

var i = 0;
while (i < n) {

// This computes
// (c, w[2 * i]) = w[2 * i] + x[i] * x[i],
// where the result is interpreted as a pair of integers of
// sizes (28 + 1, 28):

var l = x[i] & 0x3fff;
var h = x[i] >>> 14;
var cross = l * h << 1;

// This implies:
// l, h < 2^14
// cross < 2^(28 + 1)

l = (w[i << 1] | 0) + l * l +
((cross & 0x3fff) << 14);

// This implies, so we can safely use bit operators on l;
// l < 2^(28 + 2)

c = ((l >>> 28) + (cross >>> 14) + h * h) | 0;
w[i << 1] = l & 0xfffffff;

// This implies, which is a requirement for the loop.
// c < 2^(28 + 1)
//
// The standard way to do this would be to simply allow each
// w[i + n] to intermittently hold a WORDSIZE + 1 bit integer
// (or overflow register), but for 30-bit words this causes
// overflow in muladd_loop.
sc = muladd_loop(w, x, i + 1, n, x[i] << 1, i, c) + sc;
w[i + n] = sc & 0xfffffff;
sc >>>= 28;

i++;
}
};
/* jshint +W126 */ /* Stop ignoring singleGroups */
/* eslint-enable no-extra-parens */

/**
* @description Splits x into two parts l and h of equal and
* predetermined size, i.e., the lengths of the lists l and h
* determines how x is split.
* @param l Array holding most significant words of x.
* @param h Array holding most significant words of x.
* @param x Original array.
* @function karatsuba_split
* @memberof verificatum.arithm.li
*/
var karatsuba_split = function (l, h, x) {

var m = Math.min(l.length, x.length);
var i = 0;

while (i < m) {
l[i] = x[i];
i++;
}
while (i < l.length) {
l[i] = 0;
i++;
}
while (i < x.length) {
h[i - l.length] = x[i];
i++;
}
i -= l.length;
while (i < l.length) {
h[i] = 0;
i++;
}
};

/* jshint -W074 */ /* Ignore maxcomplexity. */
/**
* @description Sets w = x * x. The depth parameter determines the
* recursive depth of function calls and must be less than 3.
*
* <p>
*
* ASSUMES: x is non-negative and has L limbs and w has at least 2 * L
* limbs.
*
* <p>
*
* References: HAC <sectionsign>14.2,
* https://en.wikipedia.org/wiki/Karatsuba_algorithm
*
* @param w Array holding the result.
* @param x Factor.
* @param depth Recursion depth of the Karatsuba algorithm.
* @function square_karatsuba
* @memberof verificatum.arithm.li
*/
var square_karatsuba = (function () {

// Scratch space indexed by depth. These arrays are resized as
// needed in each call. In typical cryptographic applications big
// integers have the same size, so no resize takes place.
var scratch =
[
[[], [], [], [], [], [], []],
[[], [], [], [], [], [], []],
[[], [], [], [], [], [], []]
];

/** @lends */
return function (w, x, depth, len) {

// Access scratch space of this depth. Due to the depth-first
// structure of this algorithm no overwriting can take place.
var s = scratch[depth];
var h = s[0];
var l = s[1];
var z2 = s[2];
var z1 = s[3];
var z0 = s[4];
var xdif = s[5];

// Make sure that the arrays have proper sizes.
if (typeof len === "undefined") {
len = x.length;
}
len += len % 2;
var half_len = len >>> 1;

if (h.length !== half_len) {

resize(h, half_len);
resize(l, half_len);

resize(z2, len);
resize(z1, len);
resize(z0, len);

resize(xdif, half_len);
}

// Split the input x into higher and lower parts.
karatsuba_split(l, h, x);

if (depth < 1) {
square_naive(z2, h);
square_naive(z0, l);
} else {
square_karatsuba(z2, h, depth - 1);
square_karatsuba(z0, l, depth - 1);
}

// We guess which is bigger and correct the result if needed.
if (sub(xdif, h, l) < 0) {
sub(xdif, l, h);
}

if (depth < 1) {
square_naive(z1, xdif);
} else {
square_karatsuba(z1, xdif, depth - 1);
}

// Specialized loop to compute:
// b^2 * z2 + b * (z0 - z1 + z2) + z0
// where b = 2^(half_len * 28). We do it as follows:
// w = b^2 * z2 + b * (z0 + z2) + z0
// w = w - b * z1

var tmp;
var c = 0;
var i = 0;
while (i < half_len) {
w[i] = z0[i];
i++;
}
while (i < len) {

tmp = z0[i] + z0[i - half_len] + z2[i - half_len] + c;

// This implies, so we can safely add within 32 bits using
// unsigned left shift.
// tmp < 2^{28 + 2}

w[i] = tmp & 0xfffffff;
c = tmp >>> 28;
i++;
}
while (i < len + half_len) {
tmp = z0[i - half_len] + z2[i - half_len] + z2[i - len] + c;

// This implies, so we can safely add within 32 bits using
// unsigned left shift.
// tmp < 2^(28 + 2)

w[i] = tmp & 0xfffffff;
c = tmp >>> 28;
i++;
}
while (i < 2 * len) {
tmp = z2[i - len] + c;
w[i] = tmp & 0xfffffff;
c = tmp >>> 28;
i++;
}

// We can ignore the positive carry here, since we know that
// the final result fits within 2 * len words, but we need to
// subtract z1 at the right position.

i = half_len;
c = 0;
while (i < len + half_len) {
tmp = w[i] - z1[i - half_len] + c;
w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}
while (i < 2 * len) {
tmp = w[i] + c;
w[i] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
}
// Again, we ignore the carry.

// This guarantees that the result is correct even if w has
// more than L + L' words.
while (i < w.length) {
w[i] = 0;
i++;
}
};
})();
/* jshint +W074 */ /* Stop ignoring maxcomplexity. */

/**
* @description Sets w = x * x.
*
* <p>
*
* ASSUMES: x is non-negative with L and L' limbs respectively, and
* that w has at least L + L' limbs.
*
* <p>
*
* References: HAC 14.16.
*
* @param w Array holding the result.
* @param x Factor.
* @param len Actual lengths of inputs. Useful when stored in longer arrays.
* @function square
* @memberof verificatum.arithm.li
*/
var square = function (w, x, len) {

// Only use Karatsuba if the inputs are not too big.
var xlen = msword(x) + 1;
if (xlen > KARATSUBA_SQR_THRESHOLD) {
square_karatsuba(w, x, 0, len);
} else {
square_naive(w, x);
}
};

/**
* @description Sets w = x * y.
*
* <p>
*
* ASSUMES: x and y are both non-negative with L and L' limbs
* respectively, and that w has at least L + L' limbs.
*
* <p>
*
* References: HAC 14.12.
*
* @param w Array holding the result.
* @param x Left factor.
* @param y Right factor.
* @function mul_naive
* @memberof verificatum.arithm.li
*/
var mul_naive = function (w, x, y) {
var n = msword(x) + 1;
var t = msword(y) + 1;

setzero(w);

for (var i = 0; i < t; i++) {
w[i + n] = muladd_loop(w, x, 0, n, y[i], i, 0);
}
};

/**
* @description Sets w = x * y. The depth parameter determines the
* recursive depth of function calls and must be less than 3.
*
* <p>
*
* ASSUMES: x and y are both non-negative, with L and L' limbs
* respectively, and that w has at least L + L' limbs.
*
* <p>
*
* References: HAC <sectionsign>14.2,
* https://en.wikipedia.org/wiki/Karatsuba_algorithm
*
* @param w Array holding the result.
* @param x Left factor.
* @param y Right factor.
* @param depth Recursion depth of the Karatsuba algorithm.
* @param len Actual lengths of inputs. Useful when stored in longer arrays.
* @function mul_karatsuba
* @memberof verificatum.arithm.li
*/
var mul_karatsuba = (function () {

// Scratch space indexed by depth. These arrays are resized as
// needed in each call. In typical cryptographic applications big
// integers have the same size, so no resize takes place.
var scratch =
[
[[], [], [], [], [], [], [], [], [], [], []],
[[], [], [], [], [], [], [], [], [], [], []],
[[], [], [], [], [], [], [], [], [], [], []]
];

/** @lends */
return function (w, x, y, depth, len) {

// Access scratch space of this depth. Due to the depth-first
// structure of this algorithm no overwriting can take place.
var s = scratch[depth];
var hx = s[0];
var lx = s[1];
var hy = s[2];
var ly = s[3];
var z2 = s[4];
var z1 = s[5];
var z0 = s[6];
var xsum = s[7];
var ysum = s[8];
var tmp1 = s[9];
var tmp2 = s[10];

setzero(w);

// Make sure that the lengths of the arrays are equal and
// even.
if (typeof len === "undefined") {
len = Math.max(x.length, y.length);
}
len += len % 2;
var half_len = len >>> 1;

if (hx.length !== half_len) {

resize(hx, half_len);
resize(lx, half_len);
resize(hy, half_len);
resize(ly, half_len);

resize(z2, len);
resize(z1, len + 2);
resize(z0, len);

resize(xsum, half_len + 1);
resize(ysum, half_len + 1);

resize(tmp1, len + 2);
resize(tmp2, len + 2);
}

// Split the input x and y into higher and lower parts.
karatsuba_split(lx, hx, x);
karatsuba_split(ly, hy, y);

if (depth < 1) {
mul_naive(z2, hx, hy);
mul_naive(z0, lx, ly);
} else {
mul_karatsuba(z2, hx, hy, depth - 1);
mul_karatsuba(z0, lx, ly, depth - 1);
}

add(xsum, hx, lx);
add(ysum, hy, ly);

if (depth < 1) {
mul_naive(tmp1, xsum, ysum);
} else {
mul_karatsuba(tmp1, xsum, ysum, depth - 1);
}

sub(tmp2, tmp1, z2);
sub(z1, tmp2, z0);

// Specialized loop to combine the results.
var tmp;
var c = 0;
var i = 0;
while (i < half_len) {
w[i] = z0[i];
i++;
}
while (i < len) {
tmp = z0[i] + z1[i - half_len] + c;
w[i] = tmp & 0xfffffff;
c = tmp >>> 28;
i++;
}
while (i < len + half_len + 2) {
tmp = z1[i - half_len] + z2[i - len] + c;
w[i] = tmp & 0xfffffff;
c = tmp >>> 28;
i++;
}
while (i < 2 * len) {
tmp = z2[i - len] + c;
w[i] = tmp & 0xfffffff;
c = tmp >>> 28;
i++;
}

// This guarantees that the result is correct even if w has more
// than L + L' words.
while (i < w.length) {
w[i] = 0;
i++;
}
};
})();

/**
* @description Sets w = x * y.
*
* <p>
*
* ASSUMES: x and y are both non-negative with L and L' limbs
* respectively, and that w has at least L + L' limbs.
*
* @param w Array holding the result.
* @param x Left factor.
* @param y Right factor.
* @param len Actual lengths of inputs. Useful when stored in longer arrays.
* @function mul
* @memberof verificatum.arithm.li
*/
var mul = function (w, x, y, len) {

if (x === y) {
square(w, x);
} else {

// Only use Karatsuba if the inputs are relatively balanced
// and not too small.
var xlen = msword(x) + 1;
var ylen = msword(y) + 1;
if (xlen > KARATSUBA_MUL_THRESHOLD &&
Math.min(xlen / ylen, ylen / xlen) > KARATSUBA_RELATIVE) {
mul_karatsuba(w, x, y, 0, len);
} else {
mul_naive(w, x, y);
}
}
};

/* jshint -W126 */ /* Ignore singleGroups */
/* eslint-disable no-extra-parens */
/**
* @description Computes the 2-by-1 reciprocal of a word d.
*
* <p>
*
* ASSUMES: most significant bit of d is set, i.e., we have
* 2^28/2 <= d < 2^28.
*
* <p>
*
* References: Functionally equivalent to RECIPROCAL_WORD in MG.
*
* @param d Normalized divisor.
* @return 2-by-1 reciprocal of d.
* @function reciprocal_word
* @memberof verificatum.arithm.li
*/
var reciprocal_word = (function () {

// Temporary variables.
var q = [0, 0];
var a = [0, 0];
var p = [0, 0, 0];
var r = [0, 0, 0];
var one = [1];
var zero = [0];
var dd = [0];

var two_masks = [0xfffffff, 0xfffffff];

/** @lends */
return function (d) {

var s;
var N;
var A;
dd[0] = d;

set(r, two_masks);

setzero(q);
do {

// If r does not fit in a float, we shift it and the
// divisor before computing the estimated quotient.
s = Math.max(0, msbit(r) - 53);
N = r[1] * Math.pow(2, 28 - s) + (r[0] >> s);
A = Math.floor(N / d);

// Approximation of quotient as two-word integer.
a[0] = A & 0xfffffff;
a[1] = (A >>> 28);
shiftleft(a, s);

// p = a * d
mul(p, a, dd);

// Correct the estimate if needed. This should not happen,
// due to taking the floor, but floating point arithmetic
// is not robust over platforms, so let us be defensive.
while (cmp(p, r) > 0) {
sub(a, a, one);
sub(p, p, dd);
}

// r = r - q * d
sub(r, r, p);
add(q, q, a);

} while (cmp(a, zero) > 0);

// For code like this it is not robust to condition on r < d,
// since it is conceivable that A and hence a is zero despite
// that r > d. This turns out to not be the case here, but we
// write defensive code.
while (cmp(r, dd) >= 0) {
add(q, q, one);
sub(r, r, dd);
}

// q = q - 2^28
return q[0] & 0xfffffff;
};
})();

/**
* @description Computes the 3-by-2 reciprocal of d, where d has two
* limbs/words.
*
* <p>
*
* ASSUMES: most significant bit of d is set, i.e., we have
* 2^(2 * 28)/2 <= d < 2^(2*28).
*
* <p>
*
* References: Algorithm RECIPROCAL_WORD_3BY2 in MG.
*
* @param d Normalized divisor.
* @return 3-by-2 reciprocal of d.
* @function reciprocal_word_3by2
* @memberof verificatum.arithm.li
*/
var reciprocal_word_3by2 = (function () {

var t = [0, 0];

/** @lends */
return function (d) {

var v = reciprocal_word(d[1]);

// p = d1 * v mod 2^28
word_mul(t, d[1], v);

var p = t[0];

// p = p + d0 mod 2^28
p = (p + d[0]) & 0xfffffff;

// p < d0
if (p < d[0]) {
v--;

// p >= d1
if (p >= d[1]) {
v--;
p = p - d[1];
}
p = (p + 0x10000000 - d[1]) & 0xfffffff;
}

// t = p * d0
word_mul(t, v, d[0]);

// p = p + t1 mod 2^28
p = (p + t[1]) & 0xfffffff;

if (p < t[1]) {
v--;

// (p,t0) >= (d1,d0)
if (p > d[1] || (p === d[1] && t[0] >= d[0])) {
v--;
}
}
return v;
};
})();

/**
* @description Computes q and r such that u = q * d + r, where d has
* two limbs/words, d has three limbs/words, and 0 <= r < d.
*
* <p>
*
* ASSUMES: most significant bit of d is set, i.e., we have
* 2^(2 * 28)/2 <= d < 2^(2*28).
*
* <p>
*
* References: Algorithm DIV3BY2 in MG.
*
* @param r Two-word integer that ends up holding the remainder.
* @param u Three-word dividend.
* @param d Normalized divisor.
* @param neg_d Negative of d in two's complement.
* @param v 3by2 reciprocal of d.
* @return Integer quotient q = u / d.
* @function div3by2
* @memberof verificatum.arithm.li
*/
var div3by2 = (function () {

// Temporary variables.
var q = [0, 0];
var neg_t = [0, 0];

/** @lends */
return function (r, u, d, neg_d, v) {

var tmp = 0;

// (q1,q0) = v * u2
word_mul(q, v, u[2]);

// q = q + (u2,u1)
tmp = q[0] + u[1];
q[0] = tmp & 0xfffffff;
q[1] = (q[1] + u[2] + (tmp >>> 28)) & 0xfffffff;

// r1 = u1 - q1 * d1 mod 2^28
word_mul(r, q[1], d[1]);
r[1] = (u[1] + 0x10000000 - r[0]) & 0xfffffff;

// neg_t = d0 * q1
word_mul(neg_t, d[0], q[1]);
neg(neg_t, neg_t);

// r = (r1,u0) - t - d mod 2^(2 * 28)
r[0] = u[0];
tmp = r[0] + neg_t[0];
r[0] = tmp & 0xfffffff;
r[1] = (r[1] + neg_t[1] + (tmp >>> 28)) & 0xfffffff;
tmp = r[0] + neg_d[0];
r[0] = tmp & 0xfffffff;
r[1] = (r[1] + neg_d[1] + (tmp >>> 28)) & 0xfffffff;

// q1 = q1 + 1 mod 2^28
q[1] = (q[1] + 1) & 0xfffffff;

// r1 >= q0
if (r[1] >= q[0]) {

// q1 = q1 - 1 mod 2^28
q[1] = (q[1] + 0xfffffff) & 0xfffffff;

// r = r + d mod 2^(2 * 28)
tmp = r[0] + d[0];
r[0] = tmp & 0xfffffff;
r[1] = (r[1] + d[1] + (tmp >>> 28)) & 0xfffffff;
}

// r >= d
if (r[1] > d[1] || (r[1] === d[1] && r[0] >= d[0])) {

// q1 = q1 + 1
q[1] = q[1] + 1;

// r = r - d
tmp = r[0] + neg_d[0];
r[0] = tmp & 0xfffffff;
r[1] = (r[1] + neg_d[1] + (tmp >>> 28)) & 0xfffffff;
}

return q[1];
};
})();
/* jshint +W126 */ /* Stop ignoring singleGroups */
/* eslint-enable no-extra-parens */

/**
* @description Sets q and r such that x = qy + r, except that r is
* computed in place of x, so at the end of the execution x is
* identified with r. WARNING! y is cached in its normalized form
* along with its negation and reciprocal. This is pointer based,
* i.e., it is assumed that the contents of y do not change. High
* level routines must accomodate.
*
* <p>
*
* ASSUMES: x and y are positive, x has L words and at least L + 2
* limbs (i.e., two leading unused zero words), y has L' limbs, and q
* has at least L'' = max{L - L', 0} + 1 limbs and will finally hold a
* result with at most L'' words and a leading zero limb.
*
* <p>
*
* References: HAC 14.20.
*
* @param q Holder of quotient.
* @param x Divident and holder of remainder at end of computation.
* @param y Divisor.
* @function div_qr
* @memberof verificatum.arithm.li
*/
var div_qr = (function () {

// y from the previous call.
var old_y = null;

// Normalized y.
var ny = [];

// Negative of normalized y.
var neg_ny = [];

// Bits shifted left to normalize.
var normdist;

// Index of most significant word of ny.
var t;

// Reciprocal for 3by2 division.
var v;

// Most significant 3 words of x shifted to accomodate for the
// normalization of y.
var u = [0, 0, 0];

// Top two words of ny.
var d = [0, 0];

// Negative of d in two's complement.
var neg_d = [0, 0];

// Remainder in 3by2 division.
var r = [0, 0];

// Normalizes y and computes reciprocals.
var initialize_y = function (y) {

if (y === old_y) {
return;
}
old_y = y;

// Make sure we have room for a normalized copy ny of y and a
// negative of ny.
if (neg_ny.length !== y.length + 1) {
resize(neg_ny, y.length + 1);
ny.length = y.length;
}

// Make copy of y.
set(ny, y);

// Determine a normalization distance.
normdist =
(28 - (msbit(ny) + 1) % 28) % 28;

shiftleft(ny, normdist);

// Compute the negative of ny in two's complement, but drop
// the carry that equals -1 in the end. Note that neg_ny has
// one more limb than ny, which is safe since the carry is
// not used.
neg(neg_ny, ny);

// Index of most significant word of ny.
t = msword(ny);

// Extract top two words of y and their negative.
d[1] = ny[t];
d[0] = t > 0 ? ny[t - 1] : 0;
neg(neg_d, d);

// Sets the reciprocal of d.
v = reciprocal_word_3by2(d);
};

// Returns true or false depending on if x >= s(y) or not, where
// s(y) = y * 2^((n - t) * 28), i.e., s(y) is y shifted by
// n - t words to the left, and n and t are the indices of the
// most significant words of x and y respectively.
var shiftleft_ge = function (x, n, y, t) {

var i = n;
var j = t;

while (j >= 0) {
if (x[i] > y[j]) {
return true;
} else if (x[i] < y[j]) {
return false;
}
i--;
j--;
}

// When the top t + 1 words of x and s(y) are identical, we
// would compare the remaining (n + 1) - (t + 1) = n - 1
// words, but the bottom offset words of s(y) are zero, so in
// this case x >= s(y).
return true;
};

/** @lends */
return function (w, x, y) {

// Index of most significant word of x.
var n;

var i;
var j;
var k;
var l;
var tmp;
var c;

// Set quotient to zero.
setzero(w);

// If x < y, then simply return.
if (cmp(x, y) < 0) {
return;
}

// Initialize division with y. Normalization, reciprocals etc.
initialize_y(y);

// Left shift x to accomodate for normalization of y.
shiftleft(x, normdist);

// Index of most significant word of x.
n = msword(x);

// Since x > ny, we know that n >= t > 0. Pseudo-code:
//
// while (x >= ny * 2^((n - t) * wordsize)) {
//     w[n - t] = w[n - t] + 1
//     x = x - ny * 2^((n - t) * wordsize)
// }
//
// Note that due to the normalization, for random inputs the
// number of executions of this loop is probably small.
while (shiftleft_ge(x, n, ny, t)) {
i = 0;
j = n - t;
c = 0;
while (i < t + 1) {
tmp = x[j] - ny[i] + c;

x[j] = tmp & 0xfffffff;
c = tmp >> 28;
i++;
j++;
}
w[n - t]++;
}

for (i = n; i >= t + 1; i--) {

// This remains constant within each execution of the loop
// and only used for notational convenience.
k = i - t - 1;

// Estimate w[k] using reciprocal for top two words of ny.
u[2] = x[i];
u[1] = i > 0 ? x[i - 1] : 0;
u[0] = i > 1 ? x[i - 2] : 0;

if (u[2] === d[1] && u[1] >= d[0]) {
w[k] = 0xfffffff;
} else {
w[k] = div3by2(r, u, d, neg_d, v);
}

// Subtract scaled and shifted ny from x.
muladd_loop(x, neg_ny, 0, t + 2, w[k], k, 0);

// We now expect x[i] to be zero, i.e., that we have
// cancelled one word of x. In the unlikely event that the
// estimate of w[k] is too big, we need to correct the
// result by adding a scaled ny once to x.
//
// By construction 0 <= w[k] < 2^28. Thus, if w[k]
// is too big, then x[i] is -1 in two's complement, i.e.,
// equal to 0xfffffff.
if (x[k + t + 1] === 0xfffffff) {
l = 0;
j = k;
c = 0;
while (l < t + 1) {
tmp = x[j] + ny[l] + c;

x[j] = tmp & 0xfffffff;
c = tmp >> 28;
l++;
j++;
}
tmp = x[j] + c;
x[j] = tmp & 0xfffffff;
j++;
if (j < x.length) {
x[j] = 0;
}
w[k]--;
}
}

// Denormalize x.
shiftright(x, normdist);
};
})();

/**
* @description Sets w = b^e mod m.
*
* <p>
*
* ASSUMES: b >= 0, e >= 0, and m > 1, and w, b and m have L limbs.
*
* <p>
*
* References: HAC 14.82.
*
* @param w Array holding the result.
* @param b Basis integer.
* @param e Exponent.
* @param m Modulus.
* @function modpow_naive
* @memberof verificatum.arithm.li
*/
var modpow_naive = (function () {

// We use p to store squares, products, and their remainders, q to
// store quotients during modular reduction, and A to store
// intermediate results.
var p = [];
var q = [];
var A = [];

/** @lends */
return function (w, b, e, m) {

// Initialize or resize temporary space as needed.
if (A.length !== m.length) {
resize(p, 2 * m.length + 2);
resize(q, m.length);
resize(A, m.length);
}

// Index of most significant bit.
var n = msbit(e);

// We avoid one squaring.
if (getbit(e, n) === 1) {

set(p, b);
div_qr(q, p, m);
set(A, p);

}

// Iterate through the remaining bits of e starting from the
// most significant bit.
for (var i = n - 1; i >= 0; i--) {

// A = A^2 mod m.
square(p, A);

div_qr(q, p, m);
set(A, p);

if (getbit(e, i) === 1) {

// A = A * b mod m.
mul(p, A, b);
div_qr(q, p, m);
set(A, p);
}
}
set(w, A);
};
})();

/**
* @description Extracts the ith block of wordsize bits w from x
* (padding with zeros from the left) and sets uh such that:
* w = uh[0] * 2^uh[1], with uh[0] odd and with uh[0] = uh[1] = 0
* when w = 0.
* @param uh Holds the representation of word.
* @param x Contains bits.
* @param i Index of block of bits.
* @param wordsize Number of bits in each block.
* @function getuh
* @memberof verificatum.arithm.li
*/
var getuh = function (uh, x, i, wordsize) {
var bitIndex = i * wordsize;

// Get the ith block of wordsize bits.
uh[0] = 0;
for (var j = 0; j < wordsize; j++) {
uh[0] = uh[0] | getbit(x, bitIndex) << j;
bitIndex++;
}

// Extract all factors of two.
uh[1] = 0;
if (uh[0] !== 0) {
while ((uh[0] & 0x1) === 0) {
uh[0] = uh[0] >>> 1;
uh[1]++;
}
}
};

/* jshint -W074 */ /* Ignore maxcomplexity. */
/**
* @description Sets w = b^e mod m.
*
* <p>
*
* ASSUMES: b >= 0, e >= 0, and m > 1, and w, b and m have L limbs.
*
* <p>
*
* References: HAC 14.83.
*
* @param w Array holding the result.
* @param b Basis integer.
* @param e Exponent.
* @param m Modulus.
* @function modpow
* @memberof verificatum.arithm.li
*/
var modpow = (function () {

// We use p to store squares, products, and their remainders, q to
// store quotients during modular reduction, and A to store
// intermediate results.
var p = [];
var q = [];
var A = [];
var B = [];

/** @lends */
return function (w, b, e, m) {

var i;
var j;
var msb = msbit(m) + 1;

// Thresholds for pre-computation. These are somewhat
// arbitrary, since they are likely to differ with the
// wordsize and JavaScript engine.
var k = 2;
if (msb > 512) {
k++;
}
if (msb > 640) {
k++;
}
if (msb > 768) {
k++;
}
if (msb > 896) {
k++;
}
if (msb > 1280) {
k++;
}
if (msb > 2688) {
k++;
}
if (msb > 3840) {
k++;
}

// Initialize or resize temporary space as needed.
if (A.length !== m.length) {
resize(p, 2 * m.length + 2);
resize(q, m.length);
resize(A, m.length);

var len = B.length;
for (i = 0; i < len; i++) {
if (B[i].length !== m.length) {
resize(B[i], m.length);
}
}
if (len < 1 << k) {
B.length = 1 << k;
for (i = len; i < B.length; i++) {
B[i] = newarray(m.length);
}
}
}

// Precompute table
// B[0] = 1.
B[0][0] = 1;

// B[1] = b
set(B[1], b);

// B[2] = b^2 mod m
square(p, b);
div_qr(q, p, m);
set(B[2], p);

// B[i] = B[i - 1] * b^2 mod m
for (i = 1; i < 1 << k - 1; i++) {
mul(p, B[2 * i - 1], B[2]);
div_qr(q, p, m);
set(B[2 * i + 1], p);
}

// Set A = 1.
setzero(A);
A[0] = 1;

// Iterate through the bits of e starting from the most
// significant block of bits.
var n = Math.floor((msbit(e) + k - 1) / k);

var uh = [0, 0];
for (i = n; i >= 0; i--) {

// Extract the ith block of bits w and represent it as w =
// uh[0] * 2^uh[1], with uh[0] odd and with uh[0] = uh[1]
// = 0 when w = 0.
getuh(uh, e, i, k);

// A = A^E mod m, where E = 2^(k - uh[1]).
for (j = 0; j < k - uh[1]; j++) {
square(p, A);
div_qr(q, p, m);
set(A, p);
}

// A = A * B[uh[0]] mod m.
if (uh[0] !== 0) {
mul(p, A, B[uh[0]]);
div_qr(q, p, m);
set(A, p);
}

// A = A^E mod m, where E = 2^uh[1].
for (j = 0; j < uh[1]; j++) {
square(p, A);
div_qr(q, p, m);
set(A, p);
}
}
set(w, A);
};
})();
/* jshint +W074 */ /* Stop ignoring maxcomplexity. */

/**
* @description Returns a table of all possible modular products of a
* list of bases. More precisely, given a list b of k bases and a
* modulus m, it returns [k, t], where t is the table computed as t[x]
* = b[0]^x[0] * ... * b[k-1]^x[k-1] mod m, where x[i] is the ith bit
* of the integer x.
*
* <p>
*
* ASSUMES: m has L limbs and b[i] has L limbs for i = 0,...,k-1 and
* all inputs are positive.
*
* @param b List of bases.
* @param m Modulus.
* @return t Table for products.
* @class
* @memberof verificatum.arithm
*/
var modpowprodtab = (function () {

// We use p to store products and q to store quotients during
// modular reduction.
var p = [];
var q = [];

/** @lends */
return function (b, m) {

var i;
var j;

// Initialize or resize temporary space as needed.
if (q.length !== m.length) {
resize(p, 2 * m.length + 2);
resize(q, m.length);
}

// Make room for table and initialize all elements to one.
var t = [];
for (i = 0; i < 1 << b.length; i++) {
t[i] = newarray(m.length);
t[i][0] = 1;
}

// Init parts of the table with the bases provided.
for (i = 1, j = 0; i < t.length; i = i * 2, j++) {
set(t[i], b[j]);
}

// Perform precalculation using masking for efficiency.
for (var mask = 1; mask < t.length; mask++) {

var onemask = mask & -mask;
mul(p, t[mask ^ onemask], t[onemask]);
div_qr(q, p, m);
set(t[mask], p);
}

return t;
};
})();

/**
* @description Computes a simultaneous exponentiation using a table
* of pre-computed values t for k bases b[0],...,b[k-1] and modulus m,
* i.e., it sets w = b[0]^e[0] * ... * b[k-1]^e[k-1].
*
* <p>
*
* ASSUMES: m > 1 has L limbs and e[i] has L limbs for i = 0,...,k - 1
* and all inputs are positive, and that the table was computed with
* the same number k of bases and the same modulusm.
*
* @param w Holds the result.
* @param t Table of products.
* @param e List of k exponents.
* @param m Modulus
* @class
* @memberof verificatum.arithm
*/
var modpowprod = (function () {

// We use p to store squares, products, and their remainders, q to
// store quotients during modular reduction, and A to store
// intermediate results.
var p = [];
var q = [];
var A = [];

/** @lends */
return function (w, t, e, m) {

var i;

// Initialize or resize temporary space as needed.
if (A.length !== m.length) {
resize(p, 2 * m.length + 2);
resize(q, m.length);
resize(A, m.length);
}

// Determine maximal most significant bit position.
var l = msbit(e[0]);
for (i = 1; i < e.length; i++) {
l = Math.max(msbit(e[i]), l);
}

// Set A = 1.
setone(A);

for (i = l; i >= 0; i--) {

var x = 0;

// A = A^2 mod m.
square(p, A);
div_qr(q, p, m);
set(A, p);

// Loop over exponents to form a word x from all the bits
// at a given position.
for (var j = 0; j < e.length; j++) {

if (getbit(e[j], i) === 1) {

x |= 1 << j;
}
}

// Look up product in pre-computed table if needed.
if (x !== 0) {

// A = A * t[x] mod m.
mul(p, A, t[x]);
div_qr(q, p, m);
set(A, p);
}
}
set(w, A);
};
})();

/**
* @description Returns the bits between the start index and end index
* as an integer.
*
* <p>
*
* ASSUMES: s <= most significant bit of x and s < e
*
* @param x Integer to slice.
* @param s Inclusive start index.
* @param e Exclusive end index.
* @return Bits between the start index and end index as an integer.
* @method
*/
var slice = function (x, s, e) {
var m = msbit(x);

// Avoid indexing out of bounds.
e = Math.min(e, m + 1);

// Copy and get rid of the lower bits.
var w = copyarray(x);
shiftright(w, s);

// Get rid of higher words.
var bitlen = e - s;
w.length = Math.floor((bitlen + 28 - 1) / 28);

// Get rid of top-most bits.
var topbits = bitlen % 28;
if (topbits > 0) {
w[w.length - 1] &= 0xfffffff >>> 28 - topbits;
}
return w;
};

/**
* @description Returns a hexadecimal representation of this input
* array by content, i.e., unused bits of each limb are dropped before
* conversion
* @param x Array of words.
* @return Hexadecimal string representation of the array.
* @function hex
* @memberof verificatum.arithm.li
*/
var hex = function (x) {
var dense = util.change_wordsize(x, 28, 8);
normalize(dense);
return util.byteArrayToHex(dense.reverse());
};

var hex_to_li = function (s) {
var b = util.hexToByteArray(s);
var r = b.reverse();
return util.change_wordsize(r, 8, 28);
};

// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES              // DEBUG
// DEBUG                                                           // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   INSECURErandom()                                        // DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   Returns an array containing the given nominal number    // DEBUG
// DEBUG   of random bits. The random bits are NOT SECURE FOR      // DEBUG
// DEBUG   CRYPTOGRAPHIC USE.                                      // DEBUG
// DEBUG                                                           // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
var INSECURErandom = function (bitLength) {                        // DEBUG
// DEBUG
var noWords =                                                  // DEBUG
Math.floor((bitLength + 28 - 1) / 28);   // DEBUG
var zeroBits = noWords * 28 - bitLength;              // DEBUG
// DEBUG
var x = [];                                                    // DEBUG
for (var i = 0; i < noWords; i++) {                            // DEBUG
x[i] = Math.floor(Math.random() * 0x10000000);    // DEBUG
}                                                              // DEBUG
x[x.length - 1] &= 0xfffffff >>> zeroBits;                   // DEBUG
normalize(x);                                                  // DEBUG
// DEBUG
return x;                                                      // DEBUG
};                                                                 // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES     DEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG

return {
"WORDSIZE": WORDSIZE,

"newarray": newarray,
"copyarray": copyarray,
"resize": resize,
"normalize": normalize,

"setzero": setzero,
"setone": setone,
"set": set,

"msbit": msbit,
"lsbit": lsbit,
"msword": msword,

"getbit": getbit,
"iszero": iszero,
"cmp": cmp,
"shiftleft": shiftleft,
"shiftright": shiftright,

"add": add,
"sub": sub,
"mul": mul,
"mul_naive": mul_naive,
"mul_karatsuba": mul_karatsuba,
"square": square,
"square_naive": square_naive,
"square_karatsuba": square_karatsuba,

"div_qr": div_qr,
"modpow_naive": modpow_naive,
"modpow": modpow,

"modpowprodtab": modpowprodtab,
"modpowprod": modpowprod,
"slice": slice,

"hex": hex,
"hex_to_li": hex_to_li,

"muladd_loop": muladd_loop,
"neg": neg,
"reciprocal_word": reciprocal_word,
"reciprocal_word_3by2": reciprocal_word_3by2,
"div3by2": div3by2,
"word_mul": word_mul,

// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUG   WARNING! ONLY FOR DEBUGGING PURPOSES           DEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
"INSECURErandom": INSECURErandom                               // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
};

})();


// ######################################################################
// ################### sli ##############################################
// ######################################################################

/**
* Thin layer on top of the li module that provides mutable signed
* integers with basic modular arithmetic along with a few low level
* routines that requires signed integers to implement.
*
* <p>
*
* It also provides a minimal container class SLI that represents a
* signed integer. All operations on are executed on pre-existing SLI
* instances, so it is the responsibility of the programmer to ensure
* that data fits inside the allocated space.
*
* <p>
*
* This approach is motivated by the need to preserve efficiency and
* still encapsulate as much implementation details as possible.
*
* @namespace sli
* @memberof verificatum.arithm
*/
var sli = (function () {

/**
* @description Container class for signed mutable integers with space
* handled by the programmer. Instantiated with sign and value, with a
* length of the underlying array for an uninitialized instance, or
* with no parameters.
* @param first Empty, sign, or number of words in empty instance.
* @param second Empty or array containing value.
* @return Instance of a container for signed integers.
* @class SLI
* @memberof verificatum.arithm.sli
*/
function SLI(first, second) {
if (typeof first === "undefined") {
this.sign = 1;
this.value = [];
} else if (typeof second === "undefined") {
this.sign = 1;
this.value = li.newarray(first);
} else {
this.sign = first;
this.value = second;
}
this.length = this.value.length;
}
SLI.prototype = Object.create(ArithmObject.prototype);
SLI.prototype.constructor = SLI;

/**
* @description Truncates the input to the shortest possible array
* that represents the same absolute value in two's complement, i.e.,
* there is always a leading zero bit.
* @param x Array to be truncated.
* @param mask_top Word used to normalize.
* @function normalize
* @memberof verificatum.arithm.sli
*/
var normalize = function (x, mask_top) {
li.normalize(x.value, mask_top);
this.length = x.value.length;
};

/**
* @description Resizes the underlying array to the given length.
* @param a SLI to be resized.
* @param len New length of SLI.
* @function resize
* @memberof verificatum.arithm.sli
*/
var resize = function (a, len) {
li.resize(a.value, len);
a.length = a.value.length;
};

/**
* @description Returns the sign of a number.
* @param n A Javascript "number".
* @return Sign of number as -1, 0, or 1.
* @function sign
* @memberof verificatum.arithm.sli
*/
var sign = function (n) {
if (n > 0) {
return 1;
} else if (n === 0) {
return 0;
} else {
return -1;
}
};

/**
* @description Sets a = b, where b may be an SLI instance or a
* "number"
*
* <p>
*
* ASSUMES: b has L words and a has at least L limbs. If b is a
* "number", then it is assumed that 0 <= |b| < 2^28.
*
* @param a SLI holding the result.
* @param b Integer value represented as a SLI or Javascript "number".
* @function set
* @memberof verificatum.arithm.sli
*/
var set = function (a, b) {
if (typeof b === "number") {
a.sign = sign(b);
li.setzero(a.value);
a.value[0] = a.sign * b;
} else {
a.sign = b.sign;
li.set(a.value, b.value);
}
};

/**
* @description Returns a copy of a, where the length of the
* underlying array is len if this increases it.
* @param a Original array.
* @param len Length of resulting SLI if it is larger than the
* length of the original SLI.
* @return Copy of original SLI.
* @function copy
* @memberof verificatum.arithm.sli
*/
var copy = function (a, len) {
if (typeof len === "undefined") {
len = a.length;
}
return new SLI(a.sign, li.copyarray(a.value, len));
};

/**
* @description Returns -1, 0, or 1 depending on if a < b, a == b, or
* a > b.
* @param a Left SLI.
* @param b Right SLI.
* @return Value of comparison predicate on a and b.
* @function cmp
* @memberof verificatum.arithm.sli
*/
var cmp = function (a, b) {
if (a.sign < b.sign) {
return -1;
} else if (a.sign > b.sign) {
return 1;
} else if (a.sign === 0) {
return 0;
}
return li.cmp(a.value, b.value) * a.sign;
};

/**
* @description Returns true or false depending on if a = b or not.
* @param a Left SLI.
* @param b Right SLI.
* @return True or false depending on if the SLIs represent the same
* integer or not.
* @function equals
* @memberof verificatum.arithm.sli
*/
var equals = function (a, b) {
return a.sign === b.sign && li.cmp(a.value, b.value) === 0;
};

/**
* @description Returns true or false depending on a = 0 or not.
* @param a Integer represented as a SLI.
* @return True or false depending on if a is zero or not.
* @function iszero
* @memberof verificatum.arithm.sli
*/
var iszero = function (a) {
return a.sign === 0;
};

/**
* @description Returns true or false depending on a = 1 or not.
* @param a Integer represented as a SLI.
* @return True or false depending on if a is zero or not.
* @function iszero
* @memberof verificatum.arithm.sli
*/
var isone = function (a) {
return a.sign === 1 && a.value[0] === 1 && li.msword(a.value) === 0;
};

/**
* @description Shifts the given number of bits within the SLI,
* i.e., the allocated space is not expanded.
*
* <p>
*
* ASSUMES: offset >= 0.
*
* @param x SLI to be shifted.
* @param offset Number of bit positions to shift.
* @function shiftleft
* @memberof verificatum.arithm.sli
*/
var shiftleft = function (a, offset) {
li.shiftleft(a.value, offset);
};

/**
* @description Shifts the given number of bits to the right within
* the allocated space, i.e., the space is not reduced.
*
* <p>
*
* ASSUMES: offset >= 0.
*
* @param x SLI to be shifted.
* @param offset Number of bit positions to shift.
* @function shiftright
* @memberof verificatum.arithm.sli
*/
var shiftright = function (a, offset) {
li.shiftright(a.value, offset);
if (li.iszero(a.value)) {
a.sign = 0;
}
};

/**
* @description Sets a = b + c.
*
* <p>
*
* ASSUMES: b and c have B and B' bits and a can store B + B' + 1
* bits, or B + B' bits depending on if the signs of b and c are equal
* or not.
*
* @param a SLI holding the result.
* @param b Left term.
* @param c Right term.
* @function add
* @memberof verificatum.arithm.sli
*/
var add = function (a, b, c) {
var w = a.value;
var x = b.value;
var y = c.value;

// x + y  or  -x + -y.
if (b.sign === c.sign) {

li.add(w, x, y);
if (b.sign === 0) {
a.sign = -c.sign;
} else {
a.sign = b.sign;
}

// -x + y  or  x + -y.
} else {

// x >= y.
if (li.cmp(x, y) >= 0) {
li.sub(w, x, y);
a.sign = b.sign;

// x < y.
} else {
li.sub(w, y, x);
a.sign = c.sign;
}
}

if (li.iszero(w)) {
a.sign = 0;
}
};

/**
* @description Sets a = b - c.
*
* <p>
*
* ASSUMES: b and c have B and B' bits and a can store B + B' + 1
* bits, or B + B' bits depending on if the signs of b and c are
* distinct or not.
*
* @param a SLI holding the result.
* @param b Left term.
* @param c Right term.
* @function sub
* @memberof verificatum.arithm.sli
*/
var sub = function (a, b, c) {
var w = a.value;
var x = b.value;
var y = c.value;

// x - y  or  -x - -y.
if (b.sign === c.sign) {

// x >= y.
if (li.cmp(x, y) >= 0) {
li.sub(w, x, y);
a.sign = b.sign;
// x < y.
} else {
li.sub(w, y, x);
a.sign = -b.sign;
}

// -x - y  or  x - -y.
} else {

li.add(w, x, y);
if (b.sign === 0) {
a.sign = -c.sign;
} else {
a.sign = b.sign;
}
}

if (li.iszero(w)) {
a.sign = 0;
}
};

/**
* @description Sets a = b * c.
*
* <p>
*
* ASSUMES: b and c have L and L' limbs and a has at least L + L' limbs.
*
* @param a SLI holding the result.
* @param b Left factor.
* @param c Right factor.
* @function mul
* @memberof verificatum.arithm.sli
*/
var mul = (function () {

var t = [];

return function (a, b, c) {
if (a === b || a === c) {
if (t.length !== a.length) {
li.resize(t, a.length);
}
li.mul(t, b.value, c.value);
li.set(a.value, t);
} else {
li.mul(a.value, b.value, c.value);
}
a.sign = b.sign * c.sign;
};
})();

/**
* @description Sets a = b * c, where c is a Javascript "number".
*
* <p>
*
* ASSUMES: b has L limbs, c is a Javascript "number" such that 0 <=
* |c| < 2^28, and a has at least L + 1 limbs.
*
* @param a SLI holding the result.
* @param b Left factor.
* @param c Right factor.
* @function mul_number
* @memberof verificatum.arithm.sli
*/
var mul_number = (function () {
var C = new SLI(1);

/** @lends */
return function (a, b, c) {
set(C, c);
mul(a, b, C);
};
})();

/**
* @description Sets a = b^2.
*
* <p>
*
* ASSUMES: b has L words and a has at least 2 * L limbs.
*
* @param a SLI holding the result.
* @param b Factor.
* @function square
* @memberof verificatum.arithm.sli
*/
var square = function (a, b) {
li.square(a.value, b.value);
a.sign = b.sign * b.sign;
};

/**
* @description Computes q, r such that q = a / b + r with a / b and r
* rounded with sign, in particular, if b is positive, then 0 <= r <
* b. Then it sets a = r. We are faithful to the mathematical
* definition for signs.
*
* <p>
*
* ASSUMES: a and b are positive, a has L words and at least L + 2
* limbs (i.e., two leading unused zero words), b has L' limbs, and q
* has at least L'' = max{L - L', L', 0} + 1 limbs and will finally
* hold a result with at most L'' words and a leading zero limb.
*
* @param q SLI holding the quotient.
* @param a Dividend.
* @param b Divisor.
* @function div_qr
* @memberof verificatum.arithm.sli
*/
var div_qr = function (q, a, b) {

var qsign;
var asign;

li.div_qr(q.value, a.value, b.value);

// Division without remainder.
if (li.iszero(a.value)) {

qsign = a.sign * b.sign;
asign = 0;

// Division with remainder, so we need to round.
} else {

if (a.sign * b.sign === 1) {
asign = a.sign;
qsign = a.sign;
} else {

// This is safe since a.value < b.value and a.value has at
// least one more limb than b.value.
li.sub(a.value, b.value, a.value);

// This is safe, since q has an additional limb.
li.add(q, q, [1]);
asign = b.sign;
qsign = a.sign;
}
}
q.sign = qsign;
a.sign = asign;
};

/**
* @description Sets a = b mod c (this is merely syntactic sugar for
* div_qr).
* @param a SLI holding the result.
* @param b Dividend.
* @param c Modulus.
* @function mod
* @memberof verificatum.arithm.sli
*/
var mod = (function () {

// Temporary space for quotient and remainder.
var q = new SLI();
var r = new SLI();

/** @lends */
return function (a, b, c) {

// Resize temporary space if needed. This is conservative.
var qlen = b.length + 1;
if (q.length < qlen) {
resize(q, qlen);
}
var rlen = b.length + 2;
if (r.length < rlen) {
resize(r, rlen);
}

// Copy b to temporary remainder, reduce and set result.
set(r, b);
div_qr(q, r, c);
set(a, r);
};
})();

// Help function for egcd. Not exposed in interface. Consult HAC 14.61
// (5th printing + errata) for information.
var egcd_binary_reduce = function (u, A, B, x, y) {

while ((u.value[0] & 0x1) === 0) {

// u = u / 2.
shiftright(u, 1);

// A = 0 mod 2 and B = 0 mod 2.
if ((A.value[0] & 0x1) === 0 && (B.value[0] & 0x1) === 0) {

// A = A / 2 and B = B / 2.
shiftright(A, 1);
shiftright(B, 1);

} else {

// A = (A + y) / 2.
add(A, A, y);
shiftright(A, 1);

// B = (B - x) / 2.
sub(B, B, x);
shiftright(B, 1);
}
}
};

/**
* @description Sets a, b, and v such that a * x + b * y = v and v is
* the greatest common divisor of x and y.
*
* <p>
*
* References: HAC 14.61 (5th printing + errata)
*
* @param a Linear coefficient of Bezout expression.
* @param b Linear coefficient of Bezout expression.
* @param v Greatest common divisor of x and y.
* @param x Left integer.
* @param y Right integer.
* @function egcd
* @memberof verificatum.arithm.sli
*/
var egcd = (function () {

// Temporary space.
var xs = new SLI();
var ys = new SLI();

var A = new SLI();
var B = new SLI();
var C = new SLI();
var D = new SLI();

var u = new SLI();

/** @lends */
return function (a, b, v, x, y) {

if (iszero(x) || iszero(y)) {
set(a, 0);
set(b, 0);
set(v, 0);
return;
}

var len = Math.max(x.length, y.length) + 1;
if (A.length !== len) {
resize(xs, len);
resize(ys, len);

resize(A, len);
resize(B, len);
resize(C, len);
resize(D, len);
resize(u, len);
}

set(xs, x);
set(ys, y);

set(A, 1);
set(B, 0);
set(C, 0);
set(D, 1);

// Extract all common factors of two.
var common_twos = Math.min(li.lsbit(xs.value), li.lsbit(ys.value));
shiftright(xs, common_twos);
shiftright(ys, common_twos);

set(u, xs);
set(v, ys);

// Use binary laws for greatest common divisors.
while (!iszero(u)) {

egcd_binary_reduce(u, A, B, xs, ys);
egcd_binary_reduce(v, C, D, xs, ys);

if (cmp(u, v) >= 0) {

sub(u, u, v);
sub(A, A, C);
sub(B, B, D);

} else {

sub(v, v, u);
sub(C, C, A);
sub(D, D, B);
}
}

set(a, C);
set(b, D);

shiftleft(v, common_twos);
};
})();

/**
* @description Sets a such that w * x = 1 mod p.
*
* <p>
*
* ASSUMES: p > 0 is on odd prime.
*
* <p>
*
* References: HAC 14.61
*
* @param w SLI holding the result.
* @param x Integer to invert.
* @param p Positive odd prime modulus.
* @function egcd
* @memberof verificatum.arithm.sli
*/
var modinv = (function () {

// Temporary space.
var a = new SLI();
var b = new SLI();
var v = new SLI();

/** @lends */
return function (w, x, p) {

var len = Math.max(p.length, x.length);
if (a.length !== len) {
resize(a, len);
resize(b, len);
resize(v, len);
}

egcd(a, b, v, x, p);

if (a.sign < 0) {
add(w, p, a);
} else {
set(w, a);
}
};
})();

/**
* @description Sets w = b^e mod m.
*
* <p>
*
* ASSUMES: b >= 0, e >= 0, and m >= 1, and w, b and m have L limbs.
*
* @param w SLI holding the result.
* @param b Basis integer.
* @param e Exponent.
* @param m Modulus.
* @function modpow
* @memberof verificatum.arithm.sli
*/
var modpow = function (w, b, e, m) {
li.modpow(w.value, b.value, e.value, m.value);
w.sign = 1;
};

/**
* @description Returns (a | b), i.e., the Legendre symbol of a modulo
* b for an odd prime b. (This is essentially a GCD algorithm that
* keeps track of the symbol.)
*
* <p>
*
* References: HAC 2.149.
*
* @param a Integer modulo b.
* @param b An odd prime modulus.
* @return Legendre symbol of this instance modulo the input.
* @function legendre
* @memberof verificatum.arithm.sli
*/
var legendre = function (a, b) {

a = copy(a);
b = copy(b);

var s = 1;
for (;;) {

if (iszero(a)) {

return 0;

} else if (isone(a)) {

return s;

} else {

// a = 2^e * a'
var e = li.lsbit(a.value);

// a = a'.
shiftright(a, e);

// Least significant words of a and b.
var aw = a.value[0];
var bw = b.value[0];

// e = 1 mod 2 and b = 3,5 mod 8.
if (e % 2 === 1 && (bw % 8 === 3 || bw % 8 === 5)) {
s = -s;
}
// b = a = 3 mod 4.
if (bw % 4 === 3 && aw % 4 === 3) {
s = -s;
}

// Corresponds to finding the GCD.
if (isone(a)) {
return s;
}

// Replacement for recursive call.
mod(b, b, a);

var t = a;
a = b;
b = t;
}
}
};

/**
* @description Sets w to an integer such that w^2 = x mod p, i.e., it
* computes the square root of an integer modulo a positive odd prime
* employing the Shanks-Tonelli algorithm.
* @param w Holding the result.
* @param x Integer of which the square root is computed.
* @param p Positive odd prime modulus.
* @function legendre
* @memberof verificatum.arithm.sli
*/
var modsqrt = (function () {

var ONE = new SLI(1);
set(ONE, 1);

var TWO = new SLI(1);
set(TWO, 2);

var a = new SLI();
var n = new SLI();
var v = new SLI();
var k = new SLI();
var r = new SLI();
var z = new SLI();
var c = new SLI();
var tmp = new SLI();

/** @lends */
return function (w, x, p) {

var len = 2 * (li.msword(p.value) + 1);
if (a.length !== len) {
resize(a, len);
resize(n, len);
resize(v, len);
resize(k, len);
resize(r, len);
resize(z, len);
resize(c, len);
resize(tmp, len);
}
mod(a, x, p);

if (iszero(a)) {
set(w, 0);
return;
}

if (equals(p, TWO)) {
set(w, a);
return;
}

// p = 3 mod 4
if ((p.value[0] & 0x3) === 0x3) {

// v = p + 1
add(v, p, ONE);

// v = v / 4
shiftright(v, 2);

// return a^v mod p
// return --> a^((p + 1) / 4) mod p
modpow(w, a, v, p);
return;
}

// Compute k and s, where p = 2^s * (2 * k + 1) + 1

// k = p - 1
sub(k, p, ONE);

// (p - 1) = 2^s * k
var s = li.lsbit(k.value);
shiftright(k, s);

// k = k - 1
sub(k, k, ONE);

// k = k / 2
shiftright(k, 1);

// r = a^k mod p
modpow(r, a, k, p);

// n = r^2 mod p
mul(tmp, r, r);
mod(n, tmp, p);

// n = n * a mod p
mul(tmp, n, a);
mod(n, tmp, p);

// r = r * a mod p
mul(tmp, r, a);
mod(r, tmp, p);

if (isone(n)) {
set(w, r);
return;
}

// Generate a quadratic non-residue
set(z, 2);

// while z quadratic residue
while (legendre(z, p) === 1) {

// z = z + 1
add(z, z, ONE);
}

set(v, k);

// v = 2k
shiftleft(v, 1);

// v = 2k + 1
add(v, v, ONE);

// c = z^v mod p
modpow(c, z, v, p);

var t = 0;
while (cmp(n, ONE) > 0) {

// k = n
set(k, n);

// t = s
t = s;
s = 0;

// k != 1
while (!isone(k)) {

// k = k^2 mod p
mul(tmp, k, k);
mod(k, tmp, p);

// s = s + 1
s++;
}

// t = t - s
t -= s;

// v = 2^(t-1)
set(v, ONE);
shiftleft(v, t - 1);

// c = c^v mod p
modpow(tmp, c, v, p);
set(c, tmp);

// r = r * c mod p
mul(tmp, r, c);
mod(r, tmp, p);

// c = c^2 mod p
mul(tmp, c, c);
mod(c, tmp, p);

// n = n * c mod p
mul(tmp, n, c);
mod(n, tmp, p);
}
set(w, r);
};
})();

/**
* @description Returns a raw (no leading "0x" or similar) hexadecimal
* representation of the input with sign indicated by a leading "-"
* character if negative and capital characters.
* @param a SLI to represent.
* @return Hexadecimal representation of SLI.
* @function hex
* @memberof verificatum.arithm.sli
*/
var hex = function (a) {
var s = "";
if (a.sign < 0) {
s = "-";
}
return s + li.hex(a.value);
};

// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES              // DEBUG
// DEBUG                                                           // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   INSECURErandom()                                        // DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   Returns an array containing the given nominal number    // DEBUG
// DEBUG   of random bits. The random bits are NOT SECURE FOR      // DEBUG
// DEBUG   CRYPTOGRAPHIC USE.                                      // DEBUG
// DEBUG                                                           // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
var INSECURErandom = function (bitLength) {                        // DEBUG
var x = li.INSECURErandom(bitLength);                          // DEBUG
var sign = 1;                                                  // DEBUG
if (li.iszero(x)) {                                            // DEBUG
sign = 0;                                                  // DEBUG
}                                                              // DEBUG
return new SLI(sign, x);                                       // DEBUG
};                                                                 // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES     DEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG

return {
"SLI": SLI,
"set": set,
"copy": copy,
"resize": resize,
"normalize": normalize,
"cmp": cmp,
"equals": equals,
"iszero": iszero,
"shiftleft": shiftleft,
"shiftright": shiftright,
"add": add,
"sub": sub,
"mul": mul,
"mul_number": mul_number,
"square": square,
"div_qr": div_qr,
"mod": mod,
"modinv": modinv,
"egcd": egcd,
"legendre": legendre,
"modsqrt": modsqrt,
"INSECURErandom": INSECURErandom,
"hex": hex
};
})();


// ######################################################################
// ################### LargeInteger #####################################
// ######################################################################

/* jshint -W074 */ /* Ignore maxcomplexity. */
/**
* @description Class for large immutable integers that handles memory
* allocation and provided utility functions.
* @param first Can be: (1) sign of explicit integer, (2) bit length
* of random integer, (3) byte array containing the bits of an
* integer, (4) hexadecimal representation of integer, (5) byte tree
* representation of integer, or (6) Javascript "number"
* representation of integer.
*
* drb 
* Case 6 does not allow passing an integer to set the value, 
* instead is interpreted as the length of the array underlying the 
* LargeInteger, its value will be zero:
*
* sign = 0;
* value = li.newarray(first);
* drb
*
* @param second Can be: (1) value of explicit integer, (2) or source
* of randomness, or in cases (3)-(6) it must be empty.
* @class
* @memberof verificatum.arithm
*/
function LargeInteger(first, second) {
sli.SLI.call(this);

var sign;
var value;

if (typeof second !== "undefined") {

// Verbatim integer from inputs. Here first is the sign of the
// integer and second is the array representing the integer.
if (util.ofType(second, "array")) {

sign = first;
value = second;

// Non-negative random integer, here first is the bit length
// and second is a RandomSource.
} else {

var byteLength = LargeInteger.byteLengthRandom(first);
var topZeros = (8 - first % 8) % 8;

var data = second.getBytes(byteLength);

data[0] &= 0xFF >>> topZeros;
var reversed = data.reverse();

value = util.change_wordsize(reversed, 8, li.WORDSIZE);

if (li.iszero(value)) {
sign = 0;
} else {
sign = 1;
}
}

// Integer from byte array.
} else if (util.ofType(first, "array")) {

value = util.change_wordsize(first.slice().reverse(), 8, li.WORDSIZE);

if (li.iszero(value)) {
sign = 0;
} else {
sign = 1;
}

// Integer from signed hexadecimal representation.
} else if (util.ofType(first, "string")) {

// We assume that the first input is a hexadecimal value to be
// converted if only one input is given.
var hex = first;
var i = 0;

// Set the sign.
if (hex[i] === "-") {
sign = -1;
i++;
} else {
sign = 1;
}

// Ignore leading zeros.
while (i < hex.length && hex[i] === "0") {
i++;
}

// Set to zero or shorten input as appropriate.
if (i === hex.length) {
sign = 0;
hex = "00";
} else {
hex = hex.substring(i, hex.length);
}

// Convert to an array of bytes in reverse order and of proper
// wordsize.
var array = util.hexToByteArray(hex).reverse();
value = util.change_wordsize(array, 8, li.WORDSIZE);

// Create instance from byte tree.
} else if (util.ofType(first, "object")) {

if (!first.isLeaf()) {
throw Error("Expected a leaf!");
}
var tmp = new LargeInteger(first.value);
sign = tmp.sign;
value = tmp.value;

// Create empty instance to be modified by functions from sli.js.
} else if (util.ofType(first, "number")) {
sign = 0;
value = li.newarray(first);
} else {
/* istanbul ignore next */
throw Error("Invalid parameters!");
}

this.sign = sign;
this.value = value;
this.length = value.length;
}
LargeInteger.prototype = Object.create(sli.SLI.prototype);
LargeInteger.prototype.constructor = LargeInteger;

/* jshint +W074 */ /* Stop ignoring maxcomplexity. */

// ################### ZERO #############################################
// Representation of zero.
LargeInteger.ZERO = new LargeInteger(0, [0]);

// ################### ONE ##############################################
// Representation of one.
LargeInteger.ONE = new LargeInteger(1, [1]);

// ################### TWO ##############################################
// Representation of two.
LargeInteger.TWO = new LargeInteger(1, [2]);

/**
* @description Returns the number of bytes needed to generate the
* given number of bits.
* @param bitLength Number of bits.
* @return Number of bytes needed.
* @function byteLengthRandom
* @memberof verificatum.arithm.LargeInteger
*/
LargeInteger.byteLengthRandom = function (bitLength) {
return Math.floor((bitLength + 7) / 8);
};

/**
* @description Compares this integer with the input.
* @param other Other integer.
* @return -1, 0, or 1 depending on if this integer is smaller than,
* equal to, or greater than the input.
* @method
*/
LargeInteger.prototype.cmp = function (other) {
if (this.sign < other.sign) {
return -1;
} else if (this.sign > other.sign) {
return 1;
} else if (this.sign === 0) {
return 0;
}
return li.cmp(this.value, other.value) * this.sign;
};

/**
* @description Checks if this integer is equal to the input.
* @param other Other integer.
* @return true if and only if this integer equals the input.
* @method
*/
LargeInteger.prototype.equals = function (other) {
return this.cmp(other) === 0;
};

/**
* @description Checks if this integer is zero.
* @return true or false depending on if this is zero or not.
* @method
*/
LargeInteger.prototype.iszero = function () {
return this.sign === 0;
};

/**
* @description Bit length of this integer.
* @return Bit length of this integer.
* @method
*/
LargeInteger.prototype.bitLength = function () {
return li.msbit(this.value) + 1;
};

/**
* @description Returns 1 or 0 depending on if the given bit is set or
* not.
* @param index Position of bit.
* @return 1 or 0 depending on if the given bit is set or not.
* @method
*/
LargeInteger.prototype.getBit = function (index) {
return li.getbit(this.value, index);
};

/**
* @description Returns the absolute value of this integer.
* @return Absolute value of this integer.
* @method
*/
LargeInteger.prototype.abs = function () {
return new LargeInteger(1, li.copyarray(this.value));
};

/**
* @description Shifts this integer to the left.
* @param offset Bit positions to shift.
* @return This integer shifted the given number of bits to the left.
* @method
*/
LargeInteger.prototype.shiftLeft = function (offset) {
var len =
this.length + Math.floor((offset + li.WORDSIZE - 1) / li.WORDSIZE);
var value = li.copyarray(this.value);
li.resize(value, len);
li.shiftleft(value, offset);
return new LargeInteger(this.sign, value);
};

/**
* @description Shifts this integer to the right.
* @param offset Bit positions to shift.
* @return This integer shifted the given number of bits to the right.
* @method
*/
LargeInteger.prototype.shiftRight = function (offset) {
var value = li.copyarray(this.value);
li.shiftright(value, offset);
li.normalize(value);
var sign = this.sign;
if (li.iszero(value)) {
sign = 0;
}
return new LargeInteger(sign, value);
};

/**
* @description Returns negative of this integer.
* @return -this.
* @method
*/
LargeInteger.prototype.neg = function () {
return new LargeInteger(-this.sign, li.copyarray(this.value));
};

/**
* @description Computes sum of this integer and the input.
* @param term Other integer.
* @return this + term.
* @method
*/
LargeInteger.prototype.add = function (term) {
var len = Math.max(this.length, term.length) + 1;
var res = new LargeInteger(len);
sli.add(res, this, term);
sli.normalize(res);
return res;
};

/**
* @description Computes difference of this integer and the input.
* @param term Other integer.
* @return this - term.
* @method
*/
LargeInteger.prototype.sub = function (term) {
var len = Math.max(this.length, term.length) + 1;
var res = new LargeInteger(len);
sli.sub(res, this, term);
sli.normalize(res);
return res;
};

/**
* @description Computes product of this integer and the input.
* @param factor Other integer.
* @return this * term.
* @method
*/
LargeInteger.prototype.mul = function (factor) {
var len = this.length + factor.length;
var res = new LargeInteger(len);
sli.mul(res, this, factor);
sli.normalize(res);
return res;
};

/**
* @description Computes square of this integer.
* @return this * this.
* @method
*/
LargeInteger.prototype.square = function () {
var len = 2 * this.length;
var res = new LargeInteger(len);
sli.square(res, this);
sli.normalize(res);
return res;
};

/**
* @description Returns [q, r] such that q = this / divisor + r with
* this / divisor and r rounded with sign, in particular, if divisor
* is positive, then 0 <= r < divisor.
* @param divisor Divisor.
* @return Quotient and divisor.
* @method
*/
LargeInteger.prototype.divQR = function (divisor) {

if (divisor.sign === 0) {
/* istanbul ignore next */
throw Error("Attempt to divide by zero!");
}

var dlen = divisor.length;

// Copy this with extra space, since sli.div_qr is destructive.
var remainder = new LargeInteger(Math.max(this.length, dlen) + 2);
sli.set(remainder, this);

// Make room for quotient.
var qlen = Math.max(remainder.length - dlen, dlen, 0) + 1;
var quotient = new LargeInteger(qlen);

// Compute result.
sli.div_qr(quotient, remainder, divisor);

sli.normalize(quotient);
sli.normalize(remainder);

return [quotient, remainder];
};

/**
* @description Computes integer quotient of this integer and the
* input.
* @param divisor Integer divisor.
* @return this / divisor for positive integers with rounding
* according to signs.
* @method
*/
LargeInteger.prototype.div = function (divisor) {
return this.divQR(divisor)[0];
};

/**
* @description Computes integer remainder of this integer divided by
* the input as a value in [0, modulus - 1].
* @param modulus Divisor.
* @return Integer remainder.
* @method
*/
LargeInteger.prototype.mod = function (modulus) {
return this.divQR(modulus)[1];
};

/**
* @description Computes modular sum when this integer and the first
* input are non-negative and the last input is positive.
* @param term Other integer.
* @param modulus Modulus.
* @return (this + term) mod modulus.
* @method
*/
LargeInteger.prototype.modAdd = function (term, modulus) {
return this.add(term).mod(modulus);
};

/**
* @description Computes modular difference when this integer and the
* first input are non-negative and the last input is positive.
* @param term Other integer.
* @param modulus Modulus.
* @return (this - term) mod modulus.
* @method
*/
LargeInteger.prototype.modSub = function (term, modulus) {
return this.sub(term).mod(modulus);
};

/**
* @description Computes modular product when this integer and the first
* input are non-negative and the last input is positive.
* @param term Other integer.
* @param modulus Modulus.
* @return (this * term) mod modulus.
* @method
*/
LargeInteger.prototype.modMul = function (factor, modulus) {
return this.mul(factor).mod(modulus);
};

/**
* @description Computes modular power of this integer raised to the
* exponent modulo the given modulus.
* @param exponent Exponent.
* @param modulus Integer divisor.
* @param naive Optional debugging parameter that enables slower naive
* implementation.
* @return this ^ exponent mod modulus for positive integers.
* @method
*/
LargeInteger.prototype.modPow = function (exponent, modulus, naive) {

if (this.sign < 0) {
/* istanbul ignore next */
throw Error("Negative basis! (" + this.toHexString() + ")");
}
if (exponent.sign < 0) {
/* istanbul ignore next */
throw Error("Negative exponent! (" + exponent.toHexString() + ")");
}
if (modulus.sign <= 0) {
/* istanbul ignore next */
throw Error("Non-positive modulus! (" + modulus.toHexString() + ")");
}

// 0^x mod 1 = 0 for every x >= 0 is a special case.
if (modulus.equals(LargeInteger.ONE)) {
return LargeInteger.ZERO;
}

// g^0 mod x = 1 if x > 1.
if (exponent.sign === 0) {
return LargeInteger.ONE;
}

var b = this.value;
var g = b;
var e = exponent.value;
var m = modulus.value;

if (b.length > m.length) {
g = this.divQR(modulus)[1].value;
li.resize(g, m.length);
} else if (b.length < m.length) {
g = li.newarray(m.length);
li.set(g, b);
}

// Destination of final result.
var w = li.newarray(m.length);

if (naive) {
li.modpow_naive(w, g, e, m);
} else {
li.modpow(w, g, e, m);
}

if (li.iszero(w)) {
return LargeInteger.ZERO;
} else {
li.normalize(w);
return new LargeInteger(1, w);
}
};

/**
* @description Computes extended greatest common divisor.
* @param other Other integer.
* @return Array [a, b, v] such that a * this + b * other = v and v is
* the greatest common divisor of this and other.
* @method
*/
LargeInteger.prototype.egcd = function (other) {
var len = Math.max(this.length, other.length) + 1;

var a = new LargeInteger(len);
var b = new LargeInteger(len);
var v = new LargeInteger(len);

sli.egcd(a, b, v, this, other);

sli.normalize(a);
sli.normalize(b);
sli.normalize(v);

return [a, b, v];
};

/**
* @description Computes modular inverse of this integer modulo the
* input prime.
* @param prime Odd positive prime integer.
* @return Integer x such that x * this = 1 mod prime, where 0 <= x <
* prime.
* @method
*/
LargeInteger.prototype.modInv = function (prime) {

// There is no need to optimize this by using a stripped extended
// greatest common divisor algorithm.
var a = this.egcd(prime)[0];
if (a.sign < 0) {
return prime.add(a);
} else {
return a;
}
};

/**
* @description Returns (this | prime), i.e., the Legendre symbol of
* this modulo prime for an odd prime prime. (This is essentially a
* GCD algorithm that keeps track of the symbol.)
* @param prime An odd prime modulus.
* @return Legendre symbol of this instance modulo the input.
* @method
*/
LargeInteger.prototype.legendre = function (prime) {
return sli.legendre(this.mod(prime), prime);
};

/**
* @description Returns a square root of this integer modulo an odd
* prime, where this integer is a quadratic residue modulo the prime.
* @param prime An odd prime modulus.
* @return Square root of this integer modulo the input odd prime.
* @method
*/
LargeInteger.prototype.modSqrt = function (prime) {
var res = new LargeInteger(prime.length);
sli.modsqrt(res, this, prime);
sli.normalize(res);
return res;
};

/**
* @description Returns the bits between the start index and end index
* as an integer.
* @param start Inclusive start index.
* @param end Exclusive end index.
* @return Bits between the start index and end index as an integer.
* @method
*/
LargeInteger.prototype.slice = function (start, end) {
var value = li.slice(this.value, start, end);
var sign = this.sign;
if (li.iszero(value)) {
sign = 0;
}
return new LargeInteger(sign, value);
};

/**
* @description Computes a byte array that represents the absolute
* value of this integer. The parameter can be used to truncate the
* most significant bytes or to ensure that a given number of bytes
* are used, effectively padding the representation with zeros.
* @param byteSize Number of bytes used in output.
* @return Resulting array.
* @method
*/
LargeInteger.prototype.toByteArray = function (byteSize) {
var MASK_TOP_8 = 0x80;

// Convert the representation with li.WORDSIZE words into a
// representation with 8-bit words.
var dense = util.change_wordsize(this.value, li.WORDSIZE, 8);

if (typeof byteSize === "undefined") {

// Remove or add as many leading bytes as needed.
li.normalize(dense, MASK_TOP_8);
} else {

// Reduce/increase the number of bytes as requested.
li.resize(dense, byteSize);
}
return dense.reverse();
};

// drb
LargeInteger.prototype.toByteArrayNoZero = function () {
// no leading 0 bit
var MASK_TOP_8 = 0x00;
var dense = util.change_wordsize(this.value, li.WORDSIZE, 8);
li.normalize(dense, MASK_TOP_8);
return dense.reverse();
};
// drb

/**
* @description Computes a byte tree representation of this integer.
* @return Byte tree representation of this integer.
* @method
*/
LargeInteger.prototype.toByteTree = function () {
return new verificatum.eio.ByteTree(this.toByteArray());
};

/**
* @description Computes a hexadecimal representation of this integer.
* @return Hexadecimal representation of this integer.
* @method
*/
LargeInteger.prototype.toHexString = function () {
return sli.hex(this);
};

// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES              // DEBUG
// DEBUG                                                           // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   INSECURErandom()                                        // DEBUG
// DEBUG                                                           // DEBUG
// DEBUG   Returns an array containing the given nominal number    // DEBUG
// DEBUG   of random bits. The random bits are NOT SECURE FOR      // DEBUG
// DEBUG   CRYPTOGRAPHIC USE.                                      // DEBUG
// DEBUG                                                           // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
LargeInteger.INSECURErandom = function (bitLength) {               // DEBUG
var x = sli.INSECURErandom(bitLength);                         // DEBUG
return new LargeInteger(x.sign, x.value);                      // DEBUG
};                                                                 // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES     DEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG


// ######################################################################
// ################### ModPowProd ########################################
// ######################################################################

/**
* @description Pre-computes values to be used for simultaneous
* exponentiation for a given list b of k bases and a modulus m. The
* method {@link verificatum.arithm.ModPowProd#modPowProd} then takes
* a list of exponents e and outputs the modular power product
*
* <p>
*
* g[0] ^ e[0] * ... * g[k - 1] ^ e[k - 1] mod m.
*
* <p>
*
* The number of exponents must match the number of bases for which
* pre-computation is performed.
*
* @param bases List of bases.
* @param modulus Modulus.
* @class
* @memberof verificatum.arithm
*/
function ModPowProd(bases, modulus) {

var b = [];
for (var i = 0; i < bases.length; i++) {
b[i] = bases[i].value;
}

this.width = bases.length;
this.t = li.modpowprodtab(b, modulus.value);
this.modulus = modulus;
};

/**
* @description Computes a power-product using the given exponents.
* @param exponents Exponents.
* @return Power product.
* @method
*/
ModPowProd.prototype.modPowProd = function (exponents) {

if (exponents.length !== this.width) {
/* istanbul ignore next */
throw Error("Wrong number of exponents! (" +
exponents.length + " != " + this.width + ")");
}

var e = [];
for (var i = 0; i < exponents.length; i++) {
e[i] = exponents[i].value;
}

var res = new LargeInteger(this.modulus.length);
li.modpowprod(res.value, this.t, e, this.modulus.value);

if (li.iszero(res.value)) {
res.sign = 0;
} else {
res.sign = 1;
}
li.normalize(res.value);
return res;
};

/**
* @description Compute a power-product using the given bases,
* exponents, and modulus. This is a naive implementation for simple
* use and to debug {@link verificatum.arithm.ModPowProd#modPowProd}.
* @param bases Bases.
* @param exponents Exponents.
* @param modulus Modulus.
* @return Power product.
* @method
*/
ModPowProd.naive = function (bases, exponents, modulus) {
var result = LargeInteger.ONE;
for (var i = 0; i < bases.length; i++) {
result = result.modMul(bases[i].modPow(exponents[i], modulus), modulus);
}
return result;
};


// ######################################################################
// ################### FixModPow ########################################
// ######################################################################

/**
* @description Fixed-basis exponentiation based on simultantaneous
* exponentiation with exponent slicing.
*
* @param basis Basis.
* @param modulus Modulus.
* @param size Expected number of exponentiations to compute.
* @param width If given this determines the width of the pre-computed
* table, and otherwise it is chosen theoretically optimally.
* @class
* @memberof verificatum.arithm
*/
function FixModPow(basis, modulus, size, width) {

var bitLength = modulus.bitLength();

if (typeof width === "undefined") {
width = FixModPow.optimalWidth(bitLength, size);
}

// Determine the number of bits associated with each bases.
this.sliceSize = Math.floor((bitLength + width - 1) / width);

// Create radix element.
var powerBasis = LargeInteger.ONE.shiftLeft(this.sliceSize);

// Create generators.
var bases = [];
bases[0] = basis;
for (var i = 1; i < width; i++) {
bases[i] = bases[i - 1].modPow(powerBasis, modulus);
}

// Invoke the pre-computation of the simultaneous exponentiation
// code.
this.mpp = new ModPowProd(bases, modulus);
};

/**
* @description Takes the bit length of the exponents and the number
* of exponentiations that we expect to compute and returns the
* theoretically optimal width.
* @param bitLength Expected bit length of exponents.
* @param size Expected number of exponentiations to compute.
* @return Theoretically optimal choice of width for the expected bit
* length and number of exponentiations.
*/
FixModPow.optimalWidth = function (bitLength, size) {

var width = 2;
var cost = 1.5 * bitLength;
var oldCost;
do {

oldCost = cost;

// Amortized cost for table.
var t = ((1 << width) - width + bitLength) / size;

// Cost for multiplication.
var m = bitLength / width;

cost = t + m;

width++;

} while (width <= 16 && cost < oldCost);

// We reduce the theoretical value by one to account for the
// overhead.
return width - 1;
};

/**
* @description Cuts an input integer into the appropriate number of
* slices and outputs a list of integers such that the ith bit belongs
* to the ith slice.
* @param exponent Exponent.
* @return Array of exponents.
* @method
*/
FixModPow.prototype.slice = function (exponent) {

var exponents = [];

var bitLength = exponent.bitLength();
var offset = 0;
var i = 0;

while (i < this.mpp.width - 1 && offset < bitLength) {
exponents[i] = exponent.slice(offset, offset + this.sliceSize);
offset += this.sliceSize;
i++;
}

// There is no bound on the bit size of the last slice.
if (offset < bitLength) {
exponents[i] = exponent.slice(offset, bitLength);
offset += this.sliceSize;
i++;
}
while (i < this.mpp.width) {
exponents[i] = LargeInteger.ZERO;
i++;
}

return exponents;
};

/**
* @description Raises the fixed basis to the given exponent given the
* fixed modulus.
* @param exponent Exponent.
* @return Power of fixed basis to the given exponent.
* @method
*/
FixModPow.prototype.modPow = function (exponent) {
return this.mpp.modPowProd(this.slice(exponent));
};


// ######################################################################
// ################### PRing ############################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description Ring of prime characteristic.
* @class
* @abstract
* @memberof verificatum.arithm
*/
function PRing() {
};
PRing.prototype = Object.create(ArithmObject.prototype);
PRing.prototype.constructor = PRing;

/* istanbul ignore next */
/**
* @description Returns the underlying prime order field.
* @return Underlying prime order field.
* @method
*/
PRing.prototype.getPField = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Compares this ring and the input ring.
* @param other Other instance of subclass of this class.
* @return true or false depending on if this ring equals the
* other. This is based on deep comparison of content.
* @method
*/
PRing.prototype.equals = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Zero of the this ring.
* @return Zero of this ring.
* @method
*/
PRing.prototype.getZERO = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Unit element of this ring.
* @return Unit element of this ring.
* @method
*/
PRing.prototype.getONE = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Number of random bytes needed to derive a random
* element with the given statistical distance to uniform.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Number of random bytes needed to derive a random element.
* @method
*/
PRing.prototype.randomElementByteLength = function (statDist) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Generates a random element in the ring.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Randomly chosen element from the ring.
* @method
*/
PRing.prototype.randomElement = function (randomSource, statDist) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Recovers an element from the input byte tree.
* @param byteTree Byte tree representation of an element.
* @return Element represented by the byte tree.
* @method
*/
PRing.prototype.toElement = function (byteTree) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Fixed number of bytes needed to represent a ring
* element.
* @return Fixed number of bytes used to represent ring elements.
* @method
*/
PRing.prototype.getByteLength = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Fixed number of bytes that can be encoded into a ring
* element.
* @return Fixed number of bytes that can be encoded into a ring
* element.
* @method
*/
PRing.prototype.getEncodeLength = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Compiles a human readable representation of this field.
* @return Human readable representation of this field.
* @method
*/
PRing.prototype.toString = function () {
throw new Error("Abstract method!");
};


// ######################################################################
// ################### PRingElement #####################################
// ######################################################################

/**
* @description Element of ring of {@link verificatum.arithm.PRing}.
* @class
* @abstract
* @memberof verificatum.arithm
*/
function PRingElement(pRing) {
this.pRing = pRing;
};
PRingElement.prototype = Object.create(ArithmObject.prototype);
PRingElement.prototype.constructor = PRingElement;

/**
* @description Throws an error if this and the input are not
* instances of the same class and are contained in the same ring.
* @param other Other element expected to be contained in the same
* ring.
* @method
*/
PRingElement.prototype.assertType = function (other) {
if (other.getName() !== this.getName()) {
throw Error("Element of wrong class! (" +
other.getName() + " != " + this.getName() + ")");
}
if (!this.pRing.equals(other.pRing)) {
throw Error("Distinct rings");
}
};

/**
* @description Returns the ring containing this element.
* @return Ring containing this element.
* @method
*/
PRingElement.prototype.getPRing = function () {
return this.pRing;
};

/* istanbul ignore next */
/**
* @description Compares this element and the input.
* @param other Other ring element.
* @return true or false depending on if this element equals the input
* or not.
* @method
*/
PRingElement.prototype.equals = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Returns the negative of this element.
* @return Negative of this element.
* @method
*/
PRingElement.prototype.neg = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes product of this element and the input. If the
* input belongs to the ring of exponents to which this element
* belongs, then we multiply each component of this element with each
* component of the input, and otherwise we simply multiply each
* component of this element by the input directly.
* @param other Other ring element or integer.
* @return this * other.
* @method
*/
PRingElement.prototype.mul = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes the sum of this element and the input.
* @param other Other ring element from the same ring as this element.
* @return this + other.
* @method
*/
PRingElement.prototype.add = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes the difference of this element and the input.
* @param other Other ring element from the same ring as this element.
* @return this - other.
* @method
*/
PRingElement.prototype.sub = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Returns the multiplicative inverse of this element.
* @return Multiplicative inverse of this element.
* @method
*/
PRingElement.prototype.inv = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes a byte tree representation of this element.
* @return Byte tree representation of this element.
* @method
*/
PRingElement.prototype.toByteTree = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Compiles a human readable representation of this
* element. This should only be used for debugging.
* @return Human readable representation of this element.
* @method
*/
PRingElement.prototype.toString = function () {
throw new Error("Abstract method!");
};
/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */


// ######################################################################
// ################### PPRingElement ####################################
// ######################################################################
// This code becomes more complex using map, some, etc without any
// gain in speed.

/**
* @description Element of product ring over prime order fields.
* @class
* @extends verificatum.arithm.PRing
* @memberof verificatum.arithm
*/
function PPRingElement(pPRing, values) {
PRingElement.call(this, pPRing);
this.values = values;
};
PPRingElement.prototype = Object.create(PRingElement.prototype);
PPRingElement.prototype.constructor = PPRingElement;

PPRingElement.prototype.equals = function (other) {
this.assertType(other);
for (var i = 0; i < this.values.length; i++) {
if (!this.values[i].equals(other.values[i])) {
return false;
}
}
return true;
};

PPRingElement.prototype.add = function (other) {
this.assertType(other);
var values = [];
for (var i = 0; i < this.values.length; i++) {
values[i] = this.values[i].add(other.values[i]);
}
return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.sub = function (other) {
this.assertType(other);
var values = [];
for (var i = 0; i < this.values.length; i++) {
values[i] = this.values[i].sub(other.values[i]);
}
return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.neg = function () {
var values = [];
for (var i = 0; i < this.values.length; i++) {
values[i] = this.values[i].neg();
}
return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.mul = function (other) {
var i;
var values = [];
if (this.pRing.equals(other.pRing)) {
for (i = 0; i < this.values.length; i++) {
values[i] = this.values[i].mul(other.values[i]);
}
} else {
for (i = 0; i < this.values.length; i++) {
values[i] = this.values[i].mul(other);
}
}
return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.inv = function () {
var values = [];
for (var i = 0; i < this.values.length; i++) {
values[i] = this.values[i].inv();
}
return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.toByteTree = function () {
var children = [];
for (var i = 0; i < this.values.length; i++) {
children[i] = this.values[i].toByteTree();
}
return new verificatum.eio.ByteTree(children);
};

PPRingElement.prototype.toString = function () {
var s = "";
for (var i = 0; i < this.values.length; i++) {
s += "," + this.values[i].toString();
}
return "(" + s.slice(1) + ")";
};

/**
* @description ith component of this product ring element.
* @param i Index of component.
* @return ith component of this product ring element.
* @method
*/
PPRingElement.prototype.project = function (i) {
return this.values[i];
};


// ######################################################################
// ################### PPRing ###########################################
// ######################################################################

/**
* @description Product ring over prime order fields.
* @class
* @extends verificatum.arithm.PRing
* @memberof verificatum.arithm
*/
function PPRing(value, width) {
PRing.call(this);

var values;
var i;

if (verificatum.util.ofType(value, "array")) {
this.pRings = value;
} else {
this.pRings = verificatum.util.full(value, width);
}

values = [];
for (i = 0; i < this.pRings.length; i++) {
values[i] = this.pRings[i].getZERO();
}
this.ZERO = new PPRingElement(this, values);

values = [];
for (i = 0; i < this.pRings.length; i++) {
values[i] = this.pRings[i].getONE();
}
this.ONE = new PPRingElement(this, values);
this.byteLength = this.ONE.toByteTree().toByteArray().length;
};
PPRing.prototype = Object.create(PRing.prototype);
PPRing.prototype.constructor = PPRing;

PPRing.prototype.getPField = function () {
return this.pRings[0].getPField();
};

PPRing.prototype.equals = function (other) {
if (this === other) {
return true;
}
if (other.getName() !== "PPRing") {
return false;
}
if (this.pRings.length !== other.pRings.length) {
return false;
}
for (var i = 0; i < this.pRings.length; i++) {
if (!this.pRings[i].equals(other.pRings[i])) {
return false;
}
}
return true;
};

PPRing.prototype.getZERO = function () {
return this.ZERO;
};

PPRing.prototype.getONE = function () {
return this.ONE;
};

PPRing.prototype.randomElementByteLength = function (statDist) {
var byteLength = 0;
for (var i = 0; i < this.pRings.length; i++) {
byteLength += this.pRings[i].randomElementByteLength(statDist);
}
return byteLength;
};

PPRing.prototype.randomElement = function (randomSource, statDist) {
var values = [];
for (var i = 0; i < this.pRings.length; i++) {
values[i] = this.pRings[i].randomElement(randomSource, statDist);
}
return new PPRingElement(this, values);
};

PPRing.prototype.toElement = function (byteTree) {
if (!byteTree.isLeaf() ||
byteTree.value.length === this.pRings.length) {

var children = [];
for (var i = 0; i < this.pRings.length; i++) {
children[i] = this.pRings[i].toElement(byteTree.value[i]);
}
return new PPRingElement(this, children);
} else {
throw Error("Input byte tree does not represent an element!");
}
};

PPRing.prototype.getByteLength = function () {
return this.byteLength;
};

PPRing.prototype.getEncodeLength = function () {
return Math.floor((this.order.bitLength() + 1) / 8);
};

PPRing.prototype.toString = function () {
var s = "";
for (var i = 0; i < this.pRings.length; i++) {
s += "," + this.pRings[i].toString();
}
return "(" + s.slice(1) + ")";
};

/**
* @description Product width of this ring.
* @return Product width of this ring.
* @method
*/
PPRing.prototype.getWidth = function () {
return this.pRings.length;
};

/**
* @description ith component of this product ring.
* @return ith component of this product ring.
* @method
*/
PPRing.prototype.project = function (i) {
return this.pRings[i];
};

/**
* @description Forms a product element formed from the given list of
* elements which are required to belong to the corresponding
* components of this ring, or from a single element from the
* underlying ring (in which case it is simply repeated). The latter
* case requires that the product ring is formed from identical
* components.
* @return Product element formed from the inputs.
* @method
*/
PPRing.prototype.prod = function (value) {
var i;
var elements;

// List of elements.
if (verificatum.util.ofType(value, "array")) {
if (value.length === this.pRings.length) {
elements = value;
} else {
throw Error("Wrong number of elements! (" +
elements.length + " != " + this.pRings.length + ")");
}
// Repeated element.
} else {
elements = [];
for (i = 0; i < this.pRings.length; i++) {
elements[i] = value;
}
}
for (i = 0; i < this.pRings.length; i++) {
if (!elements[i].pRing.equals(this.pRings[i])) {
throw Error("Element " + i + " belongs to the wrong subring!");
}
}
return new PPRingElement(this, elements);
};


// ######################################################################
// ################### PFieldElement ####################################
// ######################################################################

/**
* @description Element of {@link verificatum.arithm.PField}.
* @class
* @extends verificatum.arithm.PRingElement
* @memberof verificatum.arithm
*/
function PFieldElement(pField, value) {
PRingElement.call(this, pField);
this.value = value;
};
PFieldElement.prototype = Object.create(PRingElement.prototype);
PFieldElement.prototype.constructor = PFieldElement;

PFieldElement.prototype.equals = function (other) {
this.assertType(other);
return this.value.cmp(other.value) === 0;
};

PFieldElement.prototype.neg = function () {
return new PFieldElement(this.pRing, this.pRing.order.sub(this.value));
};

PFieldElement.prototype.mul = function (other) {
var v;
if (util.ofType(other, PFieldElement)) {
v = this.value.modMul(other.value, this.pRing.order);
} else {
v = this.value.modMul(other, this.pRing.order);
}
return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.add = function (other) {
this.assertType(other);
var v = this.value.modAdd(other.value, this.pRing.order);
return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.sub = function (other) {
this.assertType(other);
var v = this.value.modSub(other.value, this.pRing.order);
return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.inv = function () {
var v = this.value.modInv(this.pRing.order);
return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.toByteTree = function () {
var byteLength = this.pRing.byteLength;
return new verificatum.eio.ByteTree(this.value.toByteArray(byteLength));
};

PFieldElement.prototype.toString = function () {
return this.value.toHexString();
};


// ######################################################################
// ################### PField ###########################################
// ######################################################################

/**
* @description Prime order field.
* @class
* @extends verificatum.arithm.PRing
* @memberof verificatum.arithm
*/
function PField(order) {
PRing.call(this);
if (typeof order === "number") {
this.order = new LargeInteger(order.toString(16));
} else if (util.ofType(order, "string")) {
this.order = new LargeInteger(order);
} else {
this.order = order;
}
this.bitLength = this.order.bitLength();
this.byteLength = this.order.toByteArray().length;
};
PField.prototype = Object.create(PRing.prototype);
PField.prototype.constructor = PField;

PField.prototype.getPField = function () {
return this;
};

PField.prototype.equals = function (other) {
if (this === other) {
return true;
}
if (other.getName() !== "PField") {
return false;
}
return this.order.equals(other.order);
};

PField.prototype.getZERO = function () {
return new PFieldElement(this, LargeInteger.ZERO);
};

PField.prototype.getONE = function () {
return new PFieldElement(this, LargeInteger.ONE);
};

PField.prototype.randomElementByteLength = function (statDist) {
return LargeInteger.byteLengthRandom(this.bitLength + statDist);
};

PField.prototype.randomElement = function (randomSource, statDist) {
var r = new LargeInteger(this.bitLength + statDist, randomSource);
return new PFieldElement(this, r.mod(this.order));
};

/**
* @description Recovers an element from the input byte tree, or
* directly from a raw byte array.
* @param param Byte tree representation of an element, or a raw byte array.
* @return Element represented by the input.
* @method
*/
PField.prototype.toElement = function (param) {
var integer;
if (util.ofType(param, eio.ByteTree) &&
param.isLeaf() &&
param.value.length === this.getByteLength()) {
integer = new LargeInteger(param.value);
} else {
integer = new LargeInteger(param);
}
return new PFieldElement(this, integer.mod(this.order));
};

PField.prototype.getByteLength = function () {
return this.byteLength;
};

PField.prototype.getEncodeLength = function () {
return Math.floor((this.order.bitLength() - 1) / 8);
};

PField.prototype.toString = function () {
return this.order.toHexString();
};


// ######################################################################
// ################### PGroup ###########################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description Abstract group where every non-trivial element has the
* order determined by the input PRing. We stress that this is not
* necessarily a prime order group. Each group has an associated ring
* of exponents, i.e., an instance of {@link verificatum.arithm.PRing}.
* @class
* @abstract
* @memberof verificatum.arithm
*/
function PGroup(pRing) {
this.pRing = pRing;
};
PGroup.prototype = Object.create(ArithmObject.prototype);
PGroup.prototype.constructor = PGroup;

/* jshint ignore:start */
/* eslint-disable no-use-before-define */
/**
* @description Returns the group with the given name.
* @return Named group.
* @function getPGroup
* @memberof verificatum.arithm.PGroup
*/
PGroup.getPGroup = function (groupName) {
var pGroup = ModPGroup.getPGroup(groupName);
if (pGroup !== null) {
return pGroup;
}
pGroup = ECqPGroup.getPGroup(groupName);
if (pGroup !== null) {
return pGroup;
}
throw Error("Unknown group name! (" + groupName + ")");
};
/* jshint ignore:end */
/* eslint-enable no-use-before-define */

/**
* @description Returns a product group or the input group if the
* given width equals one.
* @param pGroup Basic group.
* @param keyWidth Width of product group.
* @return Input group or product group.
* @method
* @static
*/
PGroup.getWideGroup = function (pGroup, keyWidth) {
if (keyWidth > 1) {
return new verificatum.arithm.PPGroup(pGroup, keyWidth);
} else {
return pGroup;
}
};

/* istanbul ignore next */
/**
* @description Returns the prime order group on which this group is
* defined.
* @return Underlying prime order group.
* @method
*/
PGroup.prototype.getPrimeOrderPGroup = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Compares this group and the input group.
* @param other Other instance of subclass of this class.
* @return true or false depending on if this group equals the
* other. This is based on deep comparison of content.
* @method
*/
PGroup.prototype.equals = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Order of every non-trivial element.
* @return Order of every non-trivial element.
* @method
*/
PGroup.prototype.getElementOrder = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Standard generator of this group. This is a generator
* in the sense that every element in this group can be written on the
* form g^x for an element x of the ring of exponents of this group.
* @return Standard generator of this group.
* @method
*/
PGroup.prototype.getg = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Unit element of this group.
* @return Unit element of this group.
* @method
*/
PGroup.prototype.getONE = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Recovers an element from the input byte tree.
* @param byteTree Byte tree representation of an element.
* @return Element represented by the byte tree.
* @method
*/
PGroup.prototype.toElement = function (byteTree) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Encodes the input bytes as a group element.
* @param bytes Bytes of content.
* @param startIndex Starting position of data to be encoded.
* @return Element constructed from the input byte array.
* @method
*/
PGroup.prototype.encode = function (bytes, startIndex, length) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Generates a random element in the group.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Randomly chosen element from the group.
* @method
*/
PGroup.prototype.randomElement = function (randomSource, statDist) {
throw new Error("Abstract method!");
};

/**
* @description Determines the number of bytes that can be encoded
* into a group element.
* @return Number of bytes that can be encoded into a group element.
* @method
*/
PGroup.prototype.getEncodeLength = function () {
return this.encodeLength;
};

/**
* @description Executes a benchmark of exponentiation in this group,
* potentially with fixed-basis.
* @param minSamples Minimal number of samples.
* @param exps Number of exponentiations to pre-compute for, or zero
* if no pre-computation is done.
* @param randomSource Source of randomness.
* @return Average number of milliseconds per exponentiation.
* @method
*/
PGroup.prototype.benchExp = function (minSamples, exps, randomSource) {
var g = this.getg();
var e = this.pRing.randomElement(randomSource, 50);
g = g.exp(e);

// If exps === 0, then we are not doing fixed-basis, and we set
// exps to one.
var fixed = exps > 0;
exps = Math.max(1, exps);

var start = util.time_ms();

for (var i = 0; i < minSamples; i++) {

if (fixed) {
g.fixed(exps);
}

for (var j = 0; j < exps; j++) {
e = this.pRing.randomElement(randomSource, 50);
var y = g.exp(e);
}
}
return (util.time_ms() - start) / (exps * minSamples);

};

/**
* @description Executes a benchmark of fixed-basis exponentiation in
* this group.
* @param minSamples Minimal number of samples.
* @param exps Lists of number of exponentiations.
* @param randomSource Source of randomness.
* @return Average number of milliseconds per exponentiation.
* @method
*/
PGroup.prototype.benchFixExp = function (minSamples, exps, randomSource) {
var results = [];
for (var i = 0; i < exps.length; i++) {
results[i] = this.benchExp(minSamples, exps[i], randomSource);
}
return results;
};

/**
* @description Executes a benchmark of exponentiation in all named
* groups.
* @param minSamples Minimal number of samples.
* @param randomSource Source of randomness.
* @return Average number of milliseconds per exponentiation.
* @method
*/
PGroup.benchExp = function (pGroups, minSamples, randomSource) {
var results = [];
for (var i = 0; i < pGroups.length; i++) {
results[i] = pGroups[i].benchExp(minSamples, 0, randomSource);
}
return results;
};

/**
* @description Executes a benchmark of exponentiation in all named
* groups.
* @param pGroups Benchmarked groups.
* @param minSamples Minimal number of samples.
* @param exps Lists of number of exponentiations.
* @param randomSource Source of randomness.
* @return Average number of milliseconds per exponentiation.
* @method
*/
PGroup.benchFixExp = function (pGroups, minSamples, exps, randomSource) {
var results = [];
for (var i = 0; i < pGroups.length; i++) {
results[i] = pGroups[i].benchFixExp(minSamples, exps, randomSource);
}
return results;
};


// ######################################################################
// ################### PGroupElement ####################################
// ######################################################################

/**
* @description Abstract group representing an element of {@link
* verificatum.arithm.PGroup}.
* @param pGroup Group to which this element belongs.
* @class
* @abstract
* @memberof verificatum.arithm
*/
function PGroupElement(pGroup) {
this.pGroup = pGroup;
this.fixExp = null;
this.expCounter = 0;
};
PGroupElement.prototype = Object.create(ArithmObject.prototype);
PGroupElement.prototype.constructor = PGroupElement;

/**
* @description Throws an error if this and the input are not
* instances of the same class and are contained in the same group.
* @param other Other element expected to be contained in the same
* group.
* @method
*/
PGroupElement.prototype.assertType = function (other) {
if (other.getName() !== this.getName()) {
throw Error("Element of wrong class! (" +
other.getName() + " != " + this.getName() + ")");
}
if (!this.pGroup.equals(other.pGroup)) {
throw Error("Distinct groups!");
}
};

/* istanbul ignore next */
/**
* @description Compares this element and the input.
* @param other Other group element.
* @return true or false depending on if this element equals the input
* or not.
* @method
*/
PGroupElement.prototype.equals = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes the product of this element and the input.
* @param other Other group element from the same group as this element.
* @return this * other.
* @method
*/
PGroupElement.prototype.mul = function (other) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes a power of this element. If the exponent
* belongs to the ring of exponents of the group to which this element
* belongs, then we use its component exponents for the corresponding
* components of this element. If not, then we simply use the exponent
* directly for each component of this element.
* @return Power of this element raised to the input exponent.
* @method
*/
PGroupElement.prototype.exp = function (exponent) {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Returns the inverse of this element.
* @return Inverse of this element.
* @method
*/
PGroupElement.prototype.inv = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes a byte tree representation of this element.
* @return Byte tree representation of this element.
* @method
*/
PGroupElement.prototype.toByteTree = function () {
throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Compiles a human readable representation of this
* element. This should only be used for debugging.
* @return Human readable representation of this element.
* @method
*/
PGroupElement.prototype.toString = function () {
throw new Error("Abstract method!");
};

/**
* @description Decodes the contents of a group element.
* @param destination Destination of decoded bytes.
* @param startIndex Where to start writing in destination.
* @return The number of decoded bytes.
* @method
*/
PGroupElement.prototype.decode = function (destination, startIndex) {
/* istanbul ignore next */
throw new Error("Abstract method!");
};

/**
* @description Peform pre-computations for the given number of
* fixed-basis exponentiations.
*
* @param size Expected number of exponentiations to compute.
* @method
*/
PGroupElement.prototype.fixed = function (exps) {
// By default we do nothing.
};

/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */


// ######################################################################
// ################### ModPGroupElement #################################
// ######################################################################

/**
* @description Element of {@link verificatum.arithm.ModPGroup}.
* @class
* @extends verificatum.arithm.PGroupElement
* @memberof verificatum.arithm
*/
function ModPGroupElement(pGroup, value) {
PGroupElement.call(this);
this.pGroup = pGroup;
this.value = value;
};
ModPGroupElement.prototype = Object.create(PGroupElement.prototype);
ModPGroupElement.prototype.constructor = ModPGroupElement;

ModPGroupElement.prototype.equals = function (other) {
this.assertType(other);
return this.value.equals(other.value);
};

ModPGroupElement.prototype.mul = function (factor) {
this.assertType(factor);
var value = this.value.mul(factor.value).mod(this.pGroup.modulus);
return new ModPGroupElement(this.pGroup, value);
};

ModPGroupElement.prototype.fixed = function (exponentiations) {
this.fixExp =
new FixModPow(this.value, this.pGroup.modulus, exponentiations);
};

ModPGroupElement.prototype.exp = function (exponent) {
this.expCounter++;
if (exponent.constructor === PFieldElement) {
exponent = exponent.value;
}

// Generic exponentiation.
if (this.fixExp === null) {

var value = this.value.modPow(exponent, this.pGroup.modulus);
return new ModPGroupElement(this.pGroup, value);

// Fixed-basis exponentiation.
} else {
return new ModPGroupElement(this.pGroup, this.fixExp.modPow(exponent));
}
};

ModPGroupElement.prototype.inv = function () {
var invValue = this.value.modInv(this.pGroup.modulus);
return new ModPGroupElement(this.pGroup, invValue);
};

ModPGroupElement.prototype.toByteTree = function () {
var byteArray = this.value.toByteArray(this.pGroup.modulusByteLength);
return new eio.ByteTree(byteArray);
};

// drb
ModPGroupElement.prototype.toByteTreeNoZero = function () {    
var byteArray = this.value.toByteArrayNoZero();
return new eio.ByteTree(byteArray);
};
// drb

ModPGroupElement.prototype.toString = function () {
return this.value.toHexString();
};


// ######################################################################
// ################### ModPGroup ########################################
// ######################################################################

/**
* @description Multiplicative group modulo a prime.
* @class
* @extends verificatum.arithm.PGroup
* @memberof verificatum.arithm
*/
function ModPGroup(modulus, order, gi, encoding) {
PGroup.call(this, ModPGroup.genPField(modulus, order));
if (typeof order === "undefined") {
var params = ModPGroup.getParams(modulus);
this.modulus = new LargeInteger(params[0]);
gi = new LargeInteger(params[1]);
this.encoding = 1;
} else {
this.modulus = modulus;
this.encoding = encoding;
}
this.generator = new ModPGroupElement(this, gi);

this.modulusByteLength = this.modulus.toByteArray().length;
this.ONE = new ModPGroupElement(this, LargeInteger.ONE);

// RO encoding.
if (this.encoding === 0) {

throw Error("RO encoding is not supported!");

// Safe prime encoding.
} else if (this.encoding === 1) {

this.encodeLength = Math.floor((this.modulus.bitLength() - 2) / 8) - 4;

// Subgroup encoding.
} else if (this.encoding === 2) {

throw Error("Subgroup encoding is not supported!");

} else {
throw new Error("Unsupported encoding! (" + this.encoding + ")");
}
};
ModPGroup.prototype = Object.create(PGroup.prototype);
ModPGroup.prototype.constructor = ModPGroup;

ModPGroup.genPField = function (groupName, order) {
if (typeof order === "undefined") {
var params = ModPGroup.getParams(groupName);
if (params.length < 4) {
var modulus = new LargeInteger(params[0]);
order = modulus.sub(LargeInteger.ONE).div(LargeInteger.TWO);
} else {
order = new LargeInteger(params[3]);
}
}
return new PField(order);
};

/**
* @description Recovers a ModPGroup instance from its representation
* as a byte tree.
* @param byteTree Byte tree representation of a ModPGroup instance.
* @return Instance of ModPGroup.
* @function fromByteTree
* @memberof verificatum.arithm.ModPGroup
*/
ModPGroup.fromByteTree = function (byteTree) {
if (byteTree.isLeaf()) {
throw Error("Byte tree is a leaf, expected four children!");
}
if (byteTree.value.length !== 4) {
throw Error("Wrong number of children! (" +
byteTree.value.length + " !== 4)");
}
var modulus = new LargeInteger(byteTree.value[0]);
var order = new LargeInteger(byteTree.value[1]);
var gi = new LargeInteger(byteTree.value[2]);

byteTree = byteTree.value[3];
if (!byteTree.isLeaf() || byteTree.value.length !== 4) {
throw Error("Malformed encoding number!");
}
var encoding = util.readUint32FromByteArray(byteTree.value);
if (encoding >= 4) {
throw Error("Unsupported encoding number!");
}

return new ModPGroup(modulus, order, gi, encoding);
};

/**
* @description Returns an array of all names of available
* multiplicative groups.
* @return Array of all names of available multiplicative groups.
* @function getPGroupNames
* @memberof verificatum.arithm.ModPGroup
*/
ModPGroup.getPGroupNames = function () {
return Object.keys(ModPGroup.named_groups);
};

/**
* @description Returns the group with the given name.
* @return Named group.
* @function getPGroup
* @memberof verificatum.arithm.ModPGroup
*/
ModPGroup.getPGroup = function (groupName) {
var params = ModPGroup.named_groups[groupName];
if (typeof params === "undefined") {
return null;
} else {
return new ModPGroup(groupName);
}
};

/**
* @description Returns an array of all available multiplicative groups.
* @return Array of all available multiplicative groups.
* @function getPGroups
* @memberof verificatum.arithm.ModPGroup
*/
ModPGroup.getPGroups = function () {
var pGroupNames = ModPGroup.getPGroupNames();
var pGroups = [];
for (var i = 0; i < pGroupNames.length; i++) {
pGroups[i] = new ModPGroup(pGroupNames[i]);
}
return pGroups;
};

/* eslint-disable */
ModPGroup.named_groups = {

// RFC 2409, RFC 2412, RFC 3526
"modp768":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
"02"],
"modp1024":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
"02"],
"modp1536":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
"02"],
"modp2048":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
"02"],
"modp3072":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
"02"],
"modp4096":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
"02"],
"modp6144":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
"02"],
"modp8192":
["FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF",
"02"]
};
/* eslint-enable */

ModPGroup.getParams = function (groupName) {
var params = ModPGroup.named_groups[groupName];
if (typeof params === "undefined") {
throw Error("Unknown group name! (" + groupName + ")");
} else {
return params;
}
};

ModPGroup.prototype.getPrimeOrderPGroup = function () {
return this;
};

ModPGroup.prototype.equals = function (other) {
if (this === other) {
return true;
}
if (other.getName() !== "ModPGroup") {
return false;
}
return this.modulus.equals(other.modulus) &&
this.generator.equals(other.generator) &&
this.encoding === other.encoding;
};

ModPGroup.prototype.getElementOrder = function () {
return this.pRing.order;
};

ModPGroup.prototype.getg = function () {
return this.generator;
};

ModPGroup.prototype.getONE = function () {
return this.ONE;
};

ModPGroup.prototype.toElement = function (bytes) {
// drb
/* if (!byteTree.isLeaf()) {
throw Error("Byte tree is not a leaf!");
}
if (byteTree.value.length !== this.modulusByteLength) {
throw Error("Wrong number of bytes! (" +
byteTree.value.length + " = " +
this.modulusByteLength + ")");
}*/
if (util.ofType(bytes, eio.ByteTree)) {
var byteTree = bytes;
if (!byteTree.isLeaf()) {
throw Error("Byte tree is not a leaf!");
}
if (byteTree.value.length !== this.modulusByteLength) {
throw Error("Wrong number of bytes! (" +
byteTree.value.length + " = " +
this.modulusByteLength + ")");
}
var value = new LargeInteger(byteTree.value); 
}
else {
var value = new LargeInteger(bytes);
}

if (this.encoding == 1 && value.legendre(this.modulus) !== 1) {
throw Error("Not a quadratic residue!")    
}

if (this.modulus.cmp(value) <= 0) {
throw Error("Integer representative not canonically reduced!");
}
return new ModPGroupElement(this, value);
};

// drb
ModPGroup.prototype.toElementAlt = function (byteTree) {
var value = new LargeInteger(byteTree.toByteArrayRaw());
if (this.encoding == 1 && value.legendre(this.modulus) !== 1) {
    throw Error("Not a quadratic residue!")    
}

if (this.modulus.cmp(value) <= 0) {
throw Error("Integer representative not canonically reduced!");
}
return new ModPGroupElement(this, value);
};
// drb

ModPGroup.prototype.encode = function (bytes, startIndex, length) {
var elen = this.encodeLength;

if (length > elen) {
throw Error("Input is too long! (" + length + " > " + elen + ")");
}

// Make room for a leading integer and data.
var bytesToUse = [];
bytesToUse.length = elen + 4;

// Write length of data.
verificatum.util.setUint32ToByteArray(bytesToUse, length, 0);

// Write data.
var i = startIndex;
var j = 4;
while (j < length + 4) {
bytesToUse[j] = bytes[i];
i++;
j++;
}

// Zero out the rest.
while (j < bytesToUse.length) {
bytesToUse[j] = 0;
j++;
}

// Make sure value is non-zero. (Ignored during decoding due to
// zero length.)
if (length === 0) {
bytesToUse[5] = 1;
}

// Negate if not a quadratic residue.
var value = new LargeInteger(bytesToUse);
if (value.legendre(this.modulus) !== 1) {
value = this.modulus.sub(value);
}
return new ModPGroupElement(this, value);
};

ModPGroup.prototype.randomElement = function (randomSource, statDist) {
var bits = 8 * this.modulusByteLength + statDist;
var r = new LargeInteger(bits, randomSource);
return new ModPGroupElement(this, r.mod(this.modulus));
};

ModPGroup.prototype.toString = function () {
return this.modulus.toHexString() + ":" +
this.getElementOrder().toHexString() + ":" +
this.generator.toString() + ":encoding(" + this.encoding + ")";
};

PGroupElement.prototype.decode = function (destination, startIndex) {
var i;
var j;
var val = this.pGroup.modulus.sub(this.value);
if (this.value.cmp(val) < 0) {
val = this.value;
}
var bytes = val.toByteArray();

// Slice spurious bytes if any.
var ulen = this.pGroup.encodeLength + 4;
if (bytes.length > ulen) {
bytes = bytes.slice(bytes.length - ulen);
}

// Add leading zero bytes if needed.
if (bytes.length < ulen) {
var raw = [];
i = 0;
while (i < ulen - bytes.length) {
raw[i] = 0;
i++;
}
j = 0;
while (j < bytes.length) {
raw[i] = bytes[j];
i++;
j++;
}
bytes = raw;
}

// Now we have exactly this.pGroup.encodeLength bytes.
var len = verificatum.util.readUint32FromByteArray(bytes, 0);
if (len < 0 || this.pGroup.encodeLength < len) {
throw Error("Illegal length of data! (" + len + ")");
}
i = startIndex;
j = 4;
while (j < len + 4) {
destination[i] = bytes[j];
i++;
j++;
}
return len;
};


// ######################################################################
// ################### PPGroupElement ###################################
// ######################################################################
// This code becomes more complex using map, some, etc without any
// gain in speed.

/**
* @description Element of {@link verificatum.arithm.PPGroup}.
* @class
* @extends verificatum.arithm.PGroupElement
* @memberof verificatum.arithm
*/
function PPGroupElement(pPGroup, values) {
PGroupElement.call(this, pPGroup);
this.values = values;
};
PPGroupElement.prototype = Object.create(PGroupElement.prototype);
PPGroupElement.prototype.constructor = PPGroupElement;

PPGroupElement.prototype.equals = function (other) {
this.assertType(other);
for (var i = 0; i < this.values.length; i++) {
if (!this.values[i].equals(other.values[i])) {
return false;
}
}
return true;
};

PPGroupElement.prototype.mul = function (other) {
this.assertType(other);
var values = [];
for (var i = 0; i < this.values.length; i++) {
values[i] = this.values[i].mul(other.values[i]);
}
return new PPGroupElement(this.pGroup, values);
};

PPGroupElement.prototype.exp = function (exponent) {
var i;
var values = [];

if (exponent.getName() === "PPRingElement" &&
exponent.pRing.equals(this.pGroup.pRing)) {

for (i = 0; i < this.values.length; i++) {
values[i] = this.values[i].exp(exponent.values[i]);
}
} else {
for (i = 0; i < this.values.length; i++) {
values[i] = this.values[i].exp(exponent);
}
}
return new PPGroupElement(this.pGroup, values);
};

PPGroupElement.prototype.inv = function () {
var values = [];
for (var i = 0; i < this.values.length; i++) {
values[i] = this.values[i].inv();
}
return new PPGroupElement(this.pGroup, values);
};

PPGroupElement.prototype.toByteTree = function () {
var children = [];
for (var i = 0; i < this.values.length; i++) {
children[i] = this.values[i].toByteTree();
}
return new verificatum.eio.ByteTree(children);
};

// drb
PPGroupElement.prototype.toByteTreeNoZero = function () {
var children = [];
for (var i = 0; i < this.values.length; i++) {
children[i] = this.values[i].toByteTreeNoZero();
}
return new verificatum.eio.ByteTree(children);
};
// drb

PPGroupElement.prototype.toString = function () {
var s = "";
for (var i = 0; i < this.values.length; i++) {
s += "," + this.values[i].toString();
}
return "(" + s.slice(1) + ")";
};

/**
* @description ith component of this product group element.
* @param i Index of component.
* @return ith component of this product group element.
* @method
*/
PPGroupElement.prototype.project = function (i) {
return this.values[i];
};

PPGroupElement.prototype.decode = function (destination, startIndex) {
var origStartIndex = startIndex;
for (var i = 0; i < this.values.length; i++) {
startIndex += this.values[i].decode(destination, startIndex);
}
return startIndex - origStartIndex;
};


// ######################################################################
// ################### PPGroup ##########################################
// ######################################################################

// Generates the product ring of the product group formed of the list
// of groups.
var genPRing = function (value) {
if (verificatum.util.ofType(value, "array")) {
var pRings = [];
for (var i = 0; i < value.length; i++) {
pRings[i] = value[i].pRing;
}
return new PPRing(pRings);
} else {
return value;
}
};

/**
* @description Product group of groups where all non-trivial elements
* have identical odd prime orders.
* @class
* @extends verificatum.arithm.PGroup
* @memberof verificatum.arithm
*/
function PPGroup(value, width) {
PGroup.call(this, genPRing(verificatum.util.full(value, width)));

var values;
var i;

if (verificatum.util.ofType(value, "array")) {
this.pGroups = value;
} else {
this.pGroups = verificatum.util.full(value, width);
}

this.encodeLength = 0;
for (i = 0; i < this.pGroups.length; i++) {
this.encodeLength += this.pGroups[i].encodeLength;
}

values = [];
for (i = 0; i < this.pGroups.length; i++) {
values[i] = this.pGroups[i].getg();
}
this.generator = new PPGroupElement(this, values);

values = [];
for (i = 0; i < this.pGroups.length; i++) {
values[i] = this.pGroups[i].getONE();
}
this.ONE = new PPGroupElement(this, values);
this.byteLength = this.ONE.toByteTree().toByteArray().length;
};
PPGroup.prototype = Object.create(PGroup.prototype);
PPGroup.prototype.constructor = PPGroup;

PGroup.prototype.getPrimeOrderPGroup = function () {
return this.pGroups[0].getPrimeOrderPGroup();
};

PPGroup.prototype.equals = function (other) {
if (this === other) {
return true;
}
if (other.getName() !== "PPGroup") {
return false;
}
if (this.pGroups.length !== other.pGroups.length) {
return false;
}
for (var i = 0; i < this.pGroups.length; i++) {
if (!this.pGroups[i].equals(other.pGroups[i])) {
return false;
}
}
return true;
};

/**
* @description Returns the width, i.e., the number of groups from
* which this product group is formed.
* @return Width of product.
* @method
*/
PPGroup.prototype.getWidth = function () {
return this.pGroups.length;
};

/**
* @description Returns ith factor of this product group.
* @param i Index of factor to return.
* @return Factor of this product group.
* @method
*/
PPGroup.prototype.project = function (i) {
return this.pGroups[i];
};

/**
* @description Returns an element of this group formed from elements
* of its factor groups.
* @param value Array of elements from the factor groups of this
* product group, or a single element, in which case it is assumed
* that this group is a power of a single group.
* @return Element of this group.
* @return Factor of this product group.
* @method
*/
PPGroup.prototype.prod = function (value) {
var i;
var elements;

// List of elements.
if (verificatum.util.ofType(value, "array")) {
if (value.length === this.pGroups.length) {
elements = value;
} else {
throw Error("Wrong number of elements! (" +
value.length + " != " + this.pGroups.length + ")");
}
// Repeated element.
} else {
elements = [];
for (i = 0; i < this.pGroups.length; i++) {
elements[i] = value;
}
}
for (i = 0; i < this.pGroups.length; i++) {
if (!elements[i].pGroup.equals(this.pGroups[i])) {
throw Error("Element " + i + " belongs to the wrong group!");
}
}
return new PPGroupElement(this, elements);
};

PPGroup.prototype.getElementOrder = function () {
return this.pGroups[0].getElementOrder();
};

PPGroup.prototype.getg = function () {
return this.generator;
};

PPGroup.prototype.getONE = function () {
return this.ONE;
};

PPGroup.prototype.randomElement = function (randomSource, statDist) {
var values = [];
for (var i = 0; i < this.pGroups.length; i++) {
values[i] = this.pGroups[i].randomElement(randomSource, statDist);
}
return new PPGroupElement(this, values);
};

PPGroup.prototype.toElement = function (byteTree) {
if (!byteTree.isLeaf() ||
byteTree.value.length === this.pGroups.length) {

var children = [];
for (var i = 0; i < this.pGroups.length; i++) {
children[i] = this.pGroups[i].toElement(byteTree.value[i]);
}
return new PPGroupElement(this, children);
} else {
throw Error("Input byte tree does not represent an element!");
}
};

// drb
PPGroup.prototype.toElementAlt = function (byteTree) {
if (!byteTree.isLeaf() ||
byteTree.value.length === this.pGroups.length) {

var children = [];
for (var i = 0; i < this.pGroups.length; i++) {
children[i] = this.pGroups[i].toElement(byteTree.value[i].value);
}
return new PPGroupElement(this, children);
} else {
throw Error("Input byte tree does not represent an element!");
}
};
// drb

PPGroup.prototype.getByteLength = function () {
return this.byteLength;
};

PPGroup.prototype.toString = function () {
var s = "";
for (var i = 0; i < this.pGroups.length; i++) {
s += "," + this.pGroups[i].toString();
}
return "(" + s.slice(1) + ")";
};

PPGroup.prototype.encode = function (bytes, startIndex, length) {
var elements = [];
for (var i = 0; i < this.pGroups.length; i++) {
var len = Math.min(length, this.pGroups[i].encodeLength);
elements[i] = this.pGroups[i].encode(bytes, startIndex, len);
startIndex += len;
length -= len;
}
return new PPGroupElement(this, elements);
};

PPGroup.prototype.randomElement = function (randomSource, statDist) {
var elements = [];
for (var i = 0; i < this.pGroups.length; i++) {
elements[i] = this.pGroups[i].randomElement(randomSource, statDist);
}
return new PPGroupElement(this, elements);
};

/**
* @description Recovers a PPGroup instance from its representation
* as a byte tree.
* @param byteTree Byte tree representation of a PPGroup instance.
* @return Instance of PPGroup.
* @function fromByteTree
* @memberof verificatum.arithm.PPGroup
*/
PPGroup.fromByteTree = function (byteTree) {
if (byteTree.isLeaf() || byteTree.value.length !== 2) {
throw Error("Invalid representation of a group!");
}
var atomicPGroups = PPGroup.atomicPGroups(byteTree.value[0]);
return PPGroup.fromStructure(byteTree.value[1], atomicPGroups);
};

// Recovers atomic PGroups.
PPGroup.atomicPGroups = function (byteTree) {
if (byteTree.isLeaf() || byteTree.value.length === 0) {
throw Error("Invalid representation of atomic groups!");
}
var pGroups = [];
for (var i = 0; i < byteTree.value.length; i++) {
pGroups[i] = PGroup.unmarshal(byteTree.value[i]);
}
return pGroups;
};

// Recovers PGroup from a structure and an array of atomic groups.
PPGroup.fromStructure = function (byteTree, atomicPGroups) {
if (byteTree.isLeaf()) {
if (byteTree.value.length !== 4) {
throw Error("Leaf does not contain an index!");
}
var index = verificatum.util.readUint32FromByteArray(byteTree.value);
if (index >= 0 && index < byteTree.value.length) {
return atomicPGroups[index];
} else {
throw Error("Index out of range!");
}
} else {
var bts = [];
for (var i = 0; i < byteTree.value.length; i++) {
bts[i] = PPGroup.fromStructure(byteTree.value[i], atomicPGroups);
}
return new verificatum.arithm.PPGroup(bts);
}
};


// ######################################################################
// ################### Hom ##############################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description Homomorphism from a ring to a group.
* @param domain Domain of homomorphism.
* @param range Range of homomorphism.
* @class
* @abstract
* @memberof verificatum.arithm
*/
function Hom(domain, range) {
this.domain = domain;
this.range = range;
}
Hom.prototype = Object.create(Object.prototype);
Hom.prototype.constructor = Hom;

/**
* @description Evaluates the homomorphism.
* @param value Input to the homomorphism.
* @return Value of the homomorphism at the given value.
* @method
*/
Hom.prototype.eva = function (value) {
throw new Error("Abstract method!");
};
/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */


// ######################################################################
// ################### ExpHom ###########################################
// ######################################################################

/**
* @description Exponentiation homomorphism from a ring to a
* group. Note that the group is not necessarily a prime order group,
* that the ring is not necessarily a field, and that the ring is not
* necessarily the ring of exponents of group.
* @param basis Basis element that is exponentiated.
* @param domain Domain of homomorphism, which may be a subring of the
* ring of exponents of the basis element.
* @class
* @abstract
* @memberof verificatum.arithm
*/
function ExpHom(domain, basis) {
Hom.call(this, domain, basis.pGroup);
this.basis = basis;
}
ExpHom.prototype = Object.create(Hom.prototype);
ExpHom.prototype.constructor = ExpHom;

ExpHom.prototype.eva = function (value) {
return this.basis.exp(value);
};

// We only expose top-level objects. All elements of rings and
// groups are instantiated through their container ring/group to
// increase robustness.
return {
"li": li,
"sli": sli,
"LargeInteger": LargeInteger,
"ModPowProd": ModPowProd,
"FixModPow": FixModPow,
"PRing": PRing,
"PField": PField,
"PPRing": PPRing,
"PGroup": PGroup,
"ModPGroup": ModPGroup,

"PPGroup": PPGroup,
"Hom": Hom,
"ExpHom": ExpHom
};
})();


// ######################################################################
// ################### crypto ###########################################
// ######################################################################

/**
* @description Cryptographic objects and algorithms.
*
* @namespace crypto
* @memberof verificatum
*/
var crypto = (function () {

var getStatDist = function (statDist) {
if (typeof statDist === "undefined") {
return 50;
} else {
return statDist;
}
};


// ##################################################################
// ############### SHA-2 ############################################
// ##################################################################

var sha256 = (function () {

/**
* @description Simplistic implementation of SHA-256 based on <a
* href="http://en.wikipedia.org/wiki/SHA-2">Wikipedia SHA-2
* pseudo-code</a>.
* @param bytes Array of bytes.
* @function hash
* @memberof verificatum.crypto.sha256
*/
var hash = (function () {

var k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

var w = [];

var rotr = function (w, r) {
return w >>> r | w << 32 - r;
};

var H;
var s0;
var s1;
var a;
var b;
var c;
var d;
var e;
var f;
var g;
var h;

var S0;
var S1;
var ch;
var maj;
var temp1;
var temp2;

var fillw = function (bytes, offset) {
var i;
var l;

// Clear contents.
for (i = 0; i < 16; i++) {
w[i] = 0;
}

// Fill words until it is complete or until we run out of
// bytes.
l = offset;
i = 0;
while (i < 16 && l < bytes.length) {
w[i] = w[i] << 8 | bytes[l];
if (l % 4 === 3) {
i++;
}
l++;
}

// If we ran out of bytes, then this is the last chunk of
// bytes and there is room for a padding byte with the leading
// bit set.
if (i < 16) {
w[i] = w[i] << 8 | 0x80;

var b = 4 - l % 4 - 1;
w[i] <<= 8 * b;
i++;
}
};

var process = function () {
var i;

// Expand to words from 16 to 64.
for (i = 16; i < 64; i++) {
s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
w[i] = w[i - 16] + s0 + w[i - 7] + s1;
}

// Working variables
a = H[0];
b = H[1];
c = H[2];
d = H[3];
e = H[4];
f = H[5];
g = H[6];
h = H[7];

for (i = 0; i < 64; i++) {

S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
ch = e & f ^ ~e & g;
temp1 = h + S1 + ch + k[i] + w[i] | 0;
S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
maj = a & b ^ a & c ^ b & c;
temp2 = S0 + maj | 0;

h = g;
g = f;
f = e;
e = d + temp1 | 0;
d = c;
c = b;
b = a;
a = temp1 + temp2 | 0;
}

H[0] = H[0] + a | 0;
H[1] = H[1] + b | 0;
H[2] = H[2] + c | 0;
H[3] = H[3] + d | 0;
H[4] = H[4] + e | 0;
H[5] = H[5] + f | 0;
H[6] = H[6] + g | 0;
H[7] = H[7] + h | 0;
};

/** @lends */
return function (bytes) {

var i;
var j;

// Initial hash value.
H = [0x6a09e667,
0xbb67ae85,
0x3c6ef372,
0xa54ff53a,
0x510e527f,
0x9b05688c,
0x1f83d9ab,
0x5be0cd19];

var bs = 16 * 4;

// Process complete blocks.
var blocks = Math.floor(bytes.length / bs);

var offset = 0;
for (j = 0; j < blocks; j++) {
fillw(bytes, offset);
process();
offset += bs;
}

var extra = bytes.length % bs;
fillw(bytes, offset);

if (extra + 9 > bs) {
process();
for (i = 0; i < 16; i++) {
w[i] = 0;
}
}

var bits = 8 * bytes.length;
w[15] = bits & 0xFFFFFFFF;
bits = Math.floor(bits / Math.pow(2, 32));
w[14] = bits & 0xFFFFFFFF;

process();

// Convert 32-bit words to 8-bit words.
var D = [];
var l = 0;
for (i = 0; i < H.length; i++) {
for (j = 3; j >= 0; j--) {
D[l] = H[i] >>> j * 8 & 0xFF;
l++;
}
}
return D;
};
})();

return {
"hash": hash
};

})();


// ##################################################################
// ############### RandomSource #####################################
// ##################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description Random source for cryptographic use.
* @class
* @memberof verificatum.crypto
*/
function RandomSource() {
};

/**
* @description Generates the given number of random bytes.
* @param len Number of bytes to generate.
* @method
*/
RandomSource.prototype.getBytes = function (len) {
throw new Error("Abstract method!");
};
/* jshint -W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */


// ##################################################################
// ############### RandomDevice #####################################
// ##################################################################

/**
* @description Random device for cryptographic use. This is a wrapper
* of a built-in source of randomness that is different depending on
* the platform. The definition depends on the platform, but
* guarantees a random output secure for cryptographic use (assuming
* that these libraries are correctly implemented).
* @class
* @memberof verificatum.crypto
*/
function RandomDevice() {
};
RandomDevice.prototype = Object.create(RandomSource.prototype);
RandomDevice.prototype.constructor = RandomDevice;

/* eslint-disable no-negated-condition */
// We are in a browser.
if (typeof window !== "undefined" && typeof window.crypto !== "undefined") {

RandomDevice.prototype.getBytes = function (len) {
var byteArray = new Uint8Array(len);
window.crypto.getRandomValues(byteArray);
var bytes = [];
for (var i = 0; i < len; i++) {
bytes[i] = byteArray[i];
}
return bytes;
};

// We are in nodejs.
} else if (typeof require !== "undefined") {

RandomDevice.prototype.getBytes = (function () {
var crypto = require("crypto");

return function (len) {
var tmp = crypto.randomBytes(len);
var res = [];
for (var i = 0; i < tmp.length; i++) {
res[i] = tmp[i];
}
return res;
};
})();

// We do not know where we are.
} else {
RandomDevice.prototype.getBytes = (function () {
return function () {
throw Error("Unable to find a suitable random device!");
};
})();
}
/* eslint-enable no-negated-condition */


// ##################################################################
// ############### SHA256PRG ########################################
// ##################################################################

/**
* @description Pseudo-random generator based on SHA-256 in counter
* mode.
* @class
* @memberof verificatum.crypto
*/
function SHA256PRG() {
this.input = null;
};
SHA256PRG.prototype = Object.create(RandomSource.prototype);
SHA256PRG.prototype.constructor = SHA256PRG;
SHA256PRG.seedLength = 32;

/**
* @description Initializes this PRG with the given seed.
* @param seed Seed bytes.
* @method
*/
SHA256PRG.prototype.setSeed = function (seed) {
if (seed.length >= 32) {
this.input = seed.slice(0, 32);
this.input.length += 4;
this.counter = 0;
this.buffer = [];
this.index = 0;
} else {
throw Error("Too short seed!");
}
};

SHA256PRG.prototype.getBytes = function (len) {
if (this.input === null) {
throw Error("Uninitialized PRG!");
}

var res = [];
res.length = len;

for (var i = 0; i < res.length; i++) {

if (this.index === this.buffer.length) {
verificatum.util.setUint32ToByteArray(this.input, this.counter, 32);
this.buffer = sha256.hash(this.input);
this.index = 0;
this.counter++;
}
res[i] = this.buffer[this.index];
this.index++;
}
return res;
};


// ######################################################################
// ################### ZKPoK ############################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description Labeled non-interactive zero-knowledge proof of
* knowledge in the random oracle model.
* @class
* @abstract
* @memberof verificatum.crypto
*/
function ZKPoK() {
};
ZKPoK.prototype = Object.create(Object.prototype);
ZKPoK.prototype.constructor = ZKPoK;

/* istanbul ignore next */
/**
* @description Number of bytes or randomness needed to compute a proof.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Number of bytes needed to compute a proof.
* @method
*/
ZKPoK.prototype.randomnessByteLength = function (statDist) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Performs pre-computation.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Pre-computed values.
* @method
*/
ZKPoK.prototype.precompute = function (randomSource, statDist) {
throw Error("Abstract method!");
};

/**
* @description Indicates if pre-computation requires the
* instance. This allows choosing the right pre-computation function.
* @return True or false depending on if pre-computation requires the
* instance or not.
* @method
*/
ZKPoK.prototype.precomputeRequiresInstance = function() {
return false;
};

/* istanbul ignore next */
/**
* @description Performs pre-computation when the instance is needed.
* @param instance Instance.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Pre-computed values.
* @method
*/
ZKPoK.prototype.precomputeWithInstance = function (instance,
randomSource,
statDist) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Completes a proof using pre-computed values.
* @param precomputed Pre-computed values.
* @param label Label as an array of bytes or byte tree.
* @param instance Instance.
* @param witness Witness of instance belonging to the right language.
* @param hashfunction Hash function used to implement the random
* oracle.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Proof in the form of a byte array.
* @method
*/
ZKPoK.prototype.completeProof = function (precomputed,
label, instance, witness,
hashfunction,
randomSource, statDist) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Verifies a proof. This is meant to be used for
* debugging, so the granularity in error handling is rudimentary.
* @param label Label as an array of bytes or byte tree.
* @param instance Instance.
* @param hashfunction Hash function used to implement the random
* oracle.
* @param proof Candidate proof in the form of a byte array.
* @return True or false depending on if the candidate proof is valid
* or not.
* @method
*/
ZKPoK.prototype.verify = function (label, instance, hashfunction, proof) {
throw Error("Abstract method!");
};

/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */

/**
* @description Computes a proof.
* @param label Label as an array of bytes or byte tree.
* @param instance Instance.
* @param witness Witness of instance belonging to the right language.
* @param hashfunction Hash function used to implement the random
* oracle.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Proof in the form of a byte array.
* @method
*/
ZKPoK.prototype.prove = function (label, instance, witness,
hashfunction, randomSource, statDist) {
var precomputed;
if (this.precomputeRequiresInstance()) {
precomputed =
this.precomputeWithInstance(instance, randomSource, statDist);
} else {
precomputed = this.precompute(randomSource, statDist);
}
return this.completeProof(precomputed, label, instance, witness,
hashfunction, randomSource, statDist);
};


// ######################################################################
// ################### SigmaProof #########################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description A public-coin three-message special sound and special
* zero-knowledge protocol, i.e., a Sigma proof, made non-interactive
* in the random oracle model using the Fiat-Shamir heuristic.
*
* <p>
*
* Recall that public-coin means that the verifier's challenge message
* is simply a random bit string and that the verdict is computed from
* the transcript. Special soundness means that given two accepting
* transcripts (A, v, k) and (A, v', k') such that v != v' a witness w
* can be computed such that (x, w) is in the NP relation (this is why
* it is a proof of knowledge). Special zero-knowledge means that
* there is an efficient simulator Sim such that for every fixed
* verifier challenge v: Sim(x, v) is identically distributed to a
* transcript of an execution on x with the verifier challenge v.
*
* <p>
*
* The Fiat-Shamir heuristic can be applied, since the protocol is
* public-coin. We use a systematic approach to generate a proper
* prefix.
*
* @class
* @abstract
* @extends verificatum.crypto.ZKPoK
* @memberof verificatum.crypto
*/
function SigmaProof() {
ZKPoK.call(this);
}
SigmaProof.prototype = Object.create(ZKPoK.prototype);
SigmaProof.prototype.constructor = SigmaProof;

/* istanbul ignore next */
/**
* @description Converts an instance to a byte tree.
* @param instance Instance.
* @return Byte tree representation of the instance.
* @method
*/
SigmaProof.prototype.instanceToByteTree = function (instance) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes a pair of updated pre-computed values and a
* commitment.
* @param precomputed Pre-computed values.
* @param instance Instance.
* @param witness Witness.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Pair of updated pre-computed values and a commitment.
* @method
*/
SigmaProof.prototype.commit = function (precomputed, instance, witness,
randomSource, statDist) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Converts a commitment to a byte tree.
* @param commitment Commitment.
* @return Byte tree representation of the commitment.
* @method
*/
SigmaProof.prototype.commitmentToByteTree = function (commitment) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Converts a byte tree to a commitment.
* @param byteTree Byte tree representation of a commitment.
* @return Commitment.
* @method
*/
SigmaProof.prototype.byteTreeToCommitment = function (byteTree) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes the challenge of the verifier using either a
* source of randomness or by applying the Fiat-Shamir heuristic to a
* byte tree using a given hash function.
* @param first Source of randomness, or data to be hashed.
* @param second Statistical distance from the uniform distribution
* assuming a perfect random source, or a hash function used to
* implement the Fiat-Shamir heuristic.
* @return Challenge of the verifier.
* @method
*/
SigmaProof.prototype.challenge = function (first, second) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes the reply of the prover.
* @param precomputed Pre-computed values needed to compute the reply.
* @param witness Witness.
* @param challenge Challenge of the verifier.
* @param randomness Randomness used to form the commitment.
* @return Reply of the prover.
* @method
*/
SigmaProof.prototype.reply = function (precomputed, witness, challenge) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Converts a reply to a byte tree.
* @param reply Reply.
* @return Byte tree representation of the reply.
* @method
*/
SigmaProof.prototype.replyToByteTree = function (reply) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Converts a byte tree to a reply.
* @param byteTree Byte tree representation of a reply.
* @return Reply.
* @method
*/
SigmaProof.prototype.byteTreeToReply = function (byteTree) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Computes the verdict of the verifier on a transcript.
* @param instance Instance.
* @param commitment Commitment.
* @param challenge Challenge of the prover.
* @param witness Witness.
* @param reply Reply.
* @return Verdict of the verifier as a boolean.
* @method
*/
SigmaProof.prototype.check = function (instance, commitment, challenge, reply) {
throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
* @description Simulates a commitment and reply for the given
* challenge.
* @param instance Instance.
* @param challenge Challenge of the verifier.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming a perfect random source.
* @return Pair of a commitment and reply.
* @method
*/
SigmaProof.prototype.simulate = function (instance, challenge,
randomSource, statDist) {
throw Error("Abstract method!");
};

/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */

SigmaProof.prototype.completeProof = function (precomputed,
label, instance, witness,
hashfunction,
randomSource, statDist) {
var pair =
this.commit(precomputed, instance, witness, randomSource, statDist);
precomputed = pair[0];
var commitment = pair[1];

// We must wrap byte array labels to get an invertible complete
// prefix. Then we simply pack label, instance, and commitment.
var lbt = eio.ByteTree.asByteTree(label);
var ibt = this.instanceToByteTree(instance);
var cbt = this.commitmentToByteTree(commitment);
var bt = new eio.ByteTree([lbt, ibt, cbt]);

var challenge = this.challenge(bt, hashfunction);

var reply = this.reply(precomputed, witness, challenge);

var rbt = this.replyToByteTree(reply);
var pbt = new eio.ByteTree([cbt, rbt]);
return pbt.toByteArray();
};

SigmaProof.prototype.verify = function (label, instance, hashfunction, proof) {
try {
var pbt = eio.ByteTree.readByteTreeFromByteArray(proof);
// drb
// if (!pbt.isLeaf() && pbt.value.length === 3) {
if (!pbt.isLeaf() && pbt.value.length >= 2) {
// drb
// We must wrap byte array labels to get an invertible
// complete prefix.
var lbt = eio.ByteTree.asByteTree(label);
var ibt = this.instanceToByteTree(instance);

var cbt = pbt.value[0];

var commitment = this.byteTreeToCommitment(cbt);

// Then we simply pack label, instance, and commitment.
var bt = new eio.ByteTree([lbt, ibt, cbt]);
var challenge = this.challenge(bt, hashfunction);

// drb
var challengeOk = true;
if(pbt.value.length === 3) {
    var inputChallenge = pbt.value[2];
    var inputChallengeElement = this.byteTreeToReply(inputChallenge);
    challengeOk = inputChallengeElement.equals(challenge);
}
// drb

var rbt = pbt.value[1];
var reply = this.byteTreeToReply(rbt);

// drb
return this.check(instance, commitment, challenge, reply) && challengeOk;
} else {
return false;
}
} catch (err) {
// drb
throw err;
// drb
return false;
}
};


// ######################################################################
// ################### SigmaProofPara ###################################
// ######################################################################

/**
* @description Parallel execution of Sigma proofs with identical
* challenge spaces. The instance, commitment and reply are
* represented as lists of instances, commitments and replies. The
* representation of the witness is specified in subclasses.
*
* @param sigmaProofs Component Sigma proofs.
* @class
* @abstract
* @extends verificatum.crypto.SigmaProof
* @memberof verificatum.crypto
*/
function SigmaProofPara(sigmaProofs) {
SigmaProof.call(this);
this.sigmaProofs = sigmaProofs;
}
SigmaProofPara.prototype = Object.create(SigmaProof.prototype);
SigmaProofPara.prototype.constructor = SigmaProofPara;

SigmaProofPara.prototype.instanceToByteTree = function (instance) {
var bta = [];
for (var i = 0; i < instance.length; i++) {
bta[i] = this.sigmaProofs[i].instanceToByteTree(instance[i]);
}
return new eio.ByteTree(bta);
};

SigmaProofPara.prototype.commitmentToByteTree = function (commitment) {
var bta = [];
for (var i = 0; i < commitment.length; i++) {
bta[i] = this.sigmaProofs[i].commitmentToByteTree(commitment[i]);
}
return new eio.ByteTree(bta);
};

SigmaProofPara.prototype.byteTreeToCommitment = function (byteTree) {
if (byteTree.isLeaf()) {
throw Error("Byte tree is a leaf!");
} else if (byteTree.value.length === this.sigmaProofs.length) {
var commitment = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
commitment[i] =
this.sigmaProofs[i].byteTreeToCommitment(byteTree.value[i]);
}
return commitment;
} else {
throw Error("Byte tree has wrong number of children! (" +
byteTree.value.length + ")");
}
};

SigmaProofPara.prototype.challenge = function (first, second) {

// Use first instance to generate challenge, since challenge
// spaces are identical.
return this.sigmaProofs[0].challenge(first, second);
};

SigmaProofPara.prototype.reply = function (precomputed, witness, challenge) {
var reply = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
reply[i] =
this.sigmaProofs[i].reply(precomputed[i], witness[i], challenge);
}
return reply;
};

SigmaProofPara.prototype.replyToByteTree = function (reply) {
var btr = [];
for (var i = 0; i < reply.length; i++) {
btr[i] = this.sigmaProofs[i].replyToByteTree(reply[i]);
}
return new eio.ByteTree(btr);
};

SigmaProofPara.prototype.byteTreeToReply = function (byteTree) {
if (byteTree.isLeaf()) {
throw Error("Byte tree is a leaf!");
} else if (byteTree.value.length === this.sigmaProofs.length) {
var reply = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
reply[i] = this.sigmaProofs[i].byteTreeToReply(byteTree.value[i]);
}
return reply;
} else {
throw Error("Byte tree has wrong number of children! (" +
byteTree.value.length + ")");
}
};

SigmaProofPara.prototype.check = function (instance, commitment,
challenge, reply) {
for (var i = 0; i < this.sigmaProofs.length; i++) {
if (!this.sigmaProofs[i].check(instance[i], commitment[i],
challenge[i], reply[i])) {
return false;
}
}
return true;
};

SigmaProofPara.prototype.simulate = function (instance, challenge,
randomSource, statDist) {
var commitment = [];
var reply = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
var pair = this.sigmaProofs[i].simulate(instance[i], challenge[i],
randomSource, statDist);
commitment[i] = pair[0];
reply[i] = pair[1];
}
return [commitment, reply];
};


// ######################################################################
// ################### SigmaProofAnd ####################################
// ######################################################################

/**
* @description Conjunction of Sigma proofs with identical challenge
* spaces.
*
* @param sigmaProofs Component Sigma proofs.
* @class
* @extends verificatum.crypto.SigmaProofPara
* @memberof verificatum.crypto
*/
function SigmaProofAnd(sigmaProofs) {
SigmaProofPara.call(this, sigmaProofs);
}
SigmaProofAnd.prototype = Object.create(SigmaProofPara.prototype);
SigmaProofAnd.prototype.constructor = SigmaProofAnd;

SigmaProofAnd.prototype.randomnessByteLength = function (statDist) {
var byteLength = 0;
for (var i = 0; i < this.sigmaProofs.length; i++) {
byteLength += this.sigmaProofs[i].randomnessByteLength(statDist);
}
return byteLength;
};

SigmaProofAnd.prototype.precompute = function (randomSource, statDist) {
var precomputed = [];

for (var i = 0; i < this.sigmaProofs.length; i++) {
precomputed[i] = this.sigmaProofs[i].precompute(randomSource, statDist);
}
return precomputed;
};

SigmaProofAnd.prototype.commit = function (precomputed, instance, witness,
randomSource, statDist) {
var newPrecomputed = [];
var commitment = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
var pair = this.sigmaProofs[i].commit(precomputed[i],
instance[i], witness[i],
randomSource, statDist);
newPrecomputed[i] = pair[0];
commitment[i] = pair[1];
}
return [newPrecomputed, commitment];
};

SigmaProofAnd.prototype.check = function (instance, commitment,
challenge, reply) {
var chall = util.fill(challenge, this.sigmaProofs.length);
return SigmaProofPara.prototype.check.call(this,
instance, commitment,
chall, reply);
};

SigmaProofAnd.prototype.simulate = function (instance, challenge,
randomSource, statDist) {
var chall = util.fill(challenge, this.sigmaProofs.length);
return SigmaProofPara.prototype.simulate.call(this,
instance, chall,
randomSource, statDist);
};


// ######################################################################
// ################### SigmaProofOr #####################################
// ######################################################################

/**
* @description Let R be an NP relation for which there is a Sigma
* proof (P, V), let c > 0 be an integer, and define the NP relation
* R(c) to consist of all pairs of the form (x, (w, i)) such that
* (x[i], w) is contained in R for some 0 <= i < c. This class gives a
* Sigma proof for R(c) provided that:
*
* <ol>
*
* <li> The challenge space of V is a finite additive group, i.e.,
*      challenges implement add() and sub() for addition and
*      subtraction, and toByteTree().
*
* <li> The challenge is uniquely determined by the proof commitment
*      and the reply. It may suffice that it is infeasible to find
*      two distinct challenges that give accepting transcripts, but
*      great care is needed.
*
* </ol>
*
* @param challengeSpace Space of challenges. This must implement a
* method toElement() that converts a byte tree to a challenge.
* @param param Array of proofs in which case the second parameter
* must not be used, or a single sigma proof in which case the second
* parameter must be a positive integer.
* @param copies Number of copies in case the first parameter is a
* single sigma proof.
* @class
* @extends verificatum.crypto.SigmaProofPara
* @memberof verificatum.crypto
*/
function SigmaProofOr(challengeSpace, param, copies) {
SigmaProofPara.call(this, param);
this.challengeSpace = challengeSpace;
this.uniform = typeof copies === "undefined";
}
SigmaProofOr.prototype = Object.create(SigmaProofPara.prototype);
SigmaProofOr.prototype.constructor = SigmaProofOr;

// Internal function.
SigmaProofOr.genSigmaProofs = function (param, copies) {
if (typeof copies === "undefined") {
return param;
} else {
return util.full(param, copies);
}
};

// Sum the elements in the array.
SigmaProofOr.sum = function (array) {
var s = array[0];
for (var j = 1; j < array.length; j++) {
s = s.add(array[j]);
}
return s;
};

SigmaProofOr.prototype.precomputeRequiresInstance = function() {
return true;
};

SigmaProofOr.prototype.precomputeWithInstance = function (instances,
randomSource,
statDist) {
// Generate challenges.
var challenges = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
challenges[i] = this.sigmaProofs[0].challenge(randomSource, statDist);
}

// Simulate each sigma proof separately with challenges.
var pre = SigmaProofPara.prototype.simulate.call(this, instances, challenges,
randomSource, statDist);
// View challenges and replies as the replies.
var precomputed = [pre[0], [challenges, pre[1]]];

// If the proofs are identical, then we pre-compute a single commitment.
if (this.uniform) {
precomputed[2] = this.sigmaProofs[0].precompute(randomSource, statDist);
}
return precomputed;
};

SigmaProofOr.prototype.commit = function (precomputed, instance, witness,
randomSource, statDist) {
var i = witness[1];

// We compute the commitment if it has not been pre-computed.
if (!this.uniform) {
precomputed[2] = this.sigmaProofs[i].precompute(randomSource, statDist);
}

// Replace the ith simulated commitment by a real commitment.
precomputed[0][i] = precomputed[2][1];

return [precomputed, precomputed[0]];
};

SigmaProofOr.prototype.reply = function (precomputed, witness, challenge) {
var i = witness[1];

// Replace the simulated ith challenge such that the challenges
// sum to the input challenge.
var sum = SigmaProofOr.sum(precomputed[1][0]);
sum = sum.sub(precomputed[1][0][i]);
precomputed[1][0][i] = challenge.sub(sum);

// Replace the simulated ith reply by computing the reply to the
// updated ith challenge.
precomputed[1][1][i] = this.sigmaProofs[i].reply(precomputed[2][0],
witness[0],
precomputed[1][0][i]);
return precomputed[1];
};

SigmaProofOr.prototype.replyToByteTree = function (reply) {
var cbts = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
cbts[i] = reply[0][i].toByteTree();
}
var cbt = new eio.ByteTree(cbts);
var rbt = SigmaProofPara.prototype.replyToByteTree.call(this, reply[1]);
return new eio.ByteTree([cbt, rbt]);
};

SigmaProofOr.prototype.byteTreeToReply = function (byteTree) {
if (!byteTree.isLeaf() && byteTree.value.length === 2) {
var cbt = byteTree.value[0];
var rbt = byteTree.value[1];

var challenge;
if (!cbt.isLeaf() && cbt.value.length === this.sigmaProofs.length) {
challenge = [];
for (var i = 0; i < this.sigmaProofs.length; i++) {
challenge[i] = this.challengeSpace.toElement(cbt.value[i]);
}
} else {
throw Error("Byte tree has wrong number of children!");
}
var reply =
SigmaProofPara.prototype.byteTreeToReply.call(this, rbt);

return [challenge, reply];
} else {
throw Error("Byte tree has wrong number of children!");
}
};

SigmaProofOr.prototype.check = function (instance, commitment,
challenge, reply) {

// Check that the sum of the individual challenges equal the
// challenge and check each individual proof independently.
var s = SigmaProofOr.sum(reply[0]);
return s.equals(challenge) &&
SigmaProofPara.prototype.check.call(this,
instance, commitment,
reply[0], reply[1]);
};

SigmaProofOr.prototype.simulate = function (instance, challenge,
randomSource, statDist) {
// Generate random challenges summing to the input challenge.
var challenges = [];
for (var i = 0; i < this.sigmaProofs.length - 1; i++) {
challenges[i] = this.sigmaProofs[0].challenge(randomSource, statDist);
}
var sum = SigmaProofOr.sum(challenges);
challenges[this.sigmaProofs.length - 1] = challenge.sub(sum);

// Simulate each sigma proof separately with challenges.
var pre = SigmaProofPara.prototype.simulate.call(this,
instance, challenges,
randomSource, statDist);
// View challenges and replies as the replies.
return [pre[0], [challenges, pre[1]]];
};


// ######################################################################
// ################### SchnorrProof #####################################
// ######################################################################

/**
* @description Sigma proof of a pre-image of a homomorphism from a
* ring to a group using a generalized Schnorr proof. More precisely,
* if Hom : R -> G is a homomorphism, where R is a product ring of a
* finite field Z/qZ of order q, and every non-trivial element in G
* has order q, then the protocol is defined as follows on common
* input x and private input w such that (x, w) is in the NP relation.
*
* <ol>
*
* <li> Prover chooses a in R randomly and computes A = Hom(a).
*
* <li> Verifier chooses a random challenge v in Z/qZ.
*
* <li> Prover computes a reply k = w * v + a in R.
*
* <li> Verifier accepts if and only if x^v * A = Hom(k), where the
*      product is taken in G.
*
* </ol>
*
* @param homomorphism Underlying homomorphism.
* @class
* @extends verificatum.crypto.SigmaProof
* @memberof verificatum.crypto
*/
function SchnorrProof(homomorphism) {
SigmaProof.call(this);
this.homomorphism = homomorphism;
}
SchnorrProof.prototype = Object.create(SigmaProof.prototype);
SchnorrProof.prototype.constructor = SchnorrProof;

SchnorrProof.prototype.randomnessByteLength = function (statDist) {
return this.homomorphism.domain.randomElementByteLength(statDist);
};

SchnorrProof.prototype.instanceToByteTree = function (instance) {
return instance.toByteTree();
};

SchnorrProof.prototype.precompute = function (randomSource, statDist) {
// A = Hom(a) for random a.
var a = this.homomorphism.domain.randomElement(randomSource, statDist);
var A = this.homomorphism.eva(a);
return [a, A];
};

SchnorrProof.prototype.commit = function (precomputed) {
// unused parameters: instance, witness, randomSource, statDist) {
return precomputed;
};

SchnorrProof.prototype.commitmentToByteTree = function (commitment) {
return commitment.toByteTree();
};

SchnorrProof.prototype.byteTreeToCommitment = function (byteTree) {
return this.homomorphism.range.toElement(byteTree);
};

SchnorrProof.prototype.challenge = function (first, second) {
if (util.ofType(first, eio.ByteTree)) {
var digest = second.hash(first.toByteArray());
return this.homomorphism.domain.getPField().toElement(digest);
} else {
return this.homomorphism.domain.randomElement(first, second);
}
};

SchnorrProof.prototype.reply = function (precomputed, witness, challenge) {
// k = w * v + a
return witness.mul(challenge).add(precomputed);
};

SchnorrProof.prototype.replyToByteTree = function (reply) {
return reply.toByteTree();
};

SchnorrProof.prototype.byteTreeToReply = function (byteTree) {
return this.homomorphism.domain.toElement(byteTree);
};

SchnorrProof.prototype.check = function (instance, commitment,
challenge, reply) {
// Check if x^v * A = Hom(k).
var ls = instance.exp(challenge).mul(commitment);
var rs = this.homomorphism.eva(reply);
return ls.equals(rs);
};

SchnorrProof.prototype.simulate = function (instance, challenge,
randomSource, statDist) {
// A = Hom(k) / x^v, for a randomly chosen random k.
var k = this.homomorphism.domain.randomElement(randomSource, statDist);
var A = this.homomorphism.eva(k).mul(instance.exp(challenge).inv());
return [A, k];
};


// ######################################################################
// ################### ElGamal ##########################################
// ######################################################################

/**
* @description The El Gamal cryptosystem implemented on top of {@link
* verificatum.arithm.PGroup}. This is a generalized implementation in
* several ways and eliminates the complexity that plagues other
* implementations by proper abstractions.
*
* <p>
*
* The first generalization allows us to use multiple El Gamal public
* keys in parallel. The second allows us to define and implement the
* Naor-Yung cryptosystem directly from the El Gamal cryptosystem and
* a proof equal exponents (see {@link
* verificatum.crypto.ElGamalZKPoK}). The third generalizes the
* cryptosystem to any width of plaintexts, i.e., lists of plaintexts
* or equivalently elements of product groups.
*
* <ul>
*
* <li> The first generalization is captured by letting the underlying
*      group G be of the form G = H^k, where H is a group of prime
*      order q and k > 0 is the key width, and the private key is
*      contained in the ring of exponents R = (Z/qZ)^k of G, where
*      Z/qZ is the field of prime order q.
*
* <li> In the standard cryptosystem the private key is an element x
*      of R, and the public key has the form (g, y), where g is an
*      element of G and y = g^x. In the second generalization we
*      instead allow the public key to be an element ((g, h), y) of
*      (G x G) x G, but still define y = g^x with x in R. Here h can
*      be defined as h = y^z for a random z in R.
*   <p>
*      The standard cryptosystem defines encryption of a message m in
*      G as Enc((g, y), m, r) = (g^r, y^r * m), where r is randomly
*      chosen in R. We generalize encryption by simply setting
*      Enc(((g, h), y), m, r) = ((g^r, h^r), y^r * m). Note that the
*      same exponent r is used for all three exponentiations and that
*      it resides in R.
*   <p>
*      The standard cryptosystem defines decryption of a ciphertext
*      (u, v) by Dec(x, (u, v)) = v / u^x. In the generalized version
*      a decryption is defined by Dec(x, ((u, a), v)) = v / u^x.
*
* <li> We generalize the cryptosystem to allow encryption of
*      plaintexts m of width w contained in G' = G^w, or equivalently
*      lists of plaintexts in G. A simple way to accomplish this with
*      a proper implementation of groups (see {@link
*      verificatum.arithm.PGroup}) is to simply widen public and
*      secret keys.
*
*      <ol>
*
*      <li> The original secret key is replaced by x' = (x, x,..., x)
*           in R' = R^w.
*
*      <li> A public key (g, y) in G x G is replaced by (g', y'),
*           where y' = (g, g,..., g) and y' = (y, y,..., y) are
*           elements in G'. Thus, the new public key is contained in
*           G' x G'.
*
*      <li> A public key ((g, h), y) in (G x G) x G is replaced by a
*           wider public key ((g', h'), y'), where g', and y' are
*           defined as above and h' is defined accordingly. Thus, the
*           new public key is contained in (G' x G') x G'.
*
*      </ol>
*
* </ul>
*
* @param standard Determines if the standard or variant El Gamal
* cryptosystem is used.
* @param pGroup Group G over which the cryptosystem is defined.
* @param random Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @class
* @memberof verificatum.crypto
*/
function ElGamal(standard, pGroup, randomSource, statDist) {
this.standard = standard;
this.pGroup = pGroup;
this.randomSource = randomSource;
this.statDist = statDist;
};
ElGamal.prototype = Object.create(Object.prototype);
ElGamal.prototype.constructor = ElGamal;

/**
* @description Computes the number of random bytes needed to encrypt.
* @return Number of random bytes needed to encrypt.
* @method
*/
ElGamal.prototype.randomnessByteLength = function (publicKey) {
publicKey.project(1).pGroup.pRing.randomElementByteLength(this.statDist);
};

/**
* @description Generates a key pair of the El Gamal cryptosystem.
* @return Pair [pk, sk] such that pk is a public key in G x G or in
* (G x G) x G depending on if the standard or variant scheme is used,
* and sk is the corresponding private key contained in R.
* @method
*/
ElGamal.prototype.gen = function () {

var pGroup = this.pGroup;

// Generate secret key.
var sk = pGroup.pRing.randomElement(this.randomSource, this.statDist);

var ghGroup;
var gh;

// Standard public key.
if (this.standard) {
ghGroup = pGroup;
gh = pGroup.getg();

// Variant public key.
} else {
var r = pGroup.pRing.randomElement(this.randomSource, this.statDist);
var h = pGroup.getg().exp(r);

ghGroup = new verificatum.arithm.PPGroup([pGroup, pGroup]);
gh = ghGroup.prod([pGroup.getg(), h]);
}
var pkGroup = new verificatum.arithm.PPGroup([ghGroup, pGroup]);
var pk = pkGroup.prod([gh, pGroup.getg().exp(sk)]);

return [pk, sk];
};

/**
* @description Pre-computation for encrypting a message using {@link
* verificatum.crypto.ElGamal.completeEncrypt}.
* @param publicKey Public key of the form (g', y'), or ((g', h'), y')
* depending on if the standard or variant scheme is used.
* @param random Randomness r in R' used for encryption. If this is
* empty, then it is generated.
* @return Triple of the form [r, u, v] or [r, (u, a), v], where u =
* (g')^r, a = (h')^r, and v = (y')^r, depending on if the standard or
* variant scheme is used.
* @method
*/
ElGamal.prototype.precomputeEncrypt = function (publicKey, random) {
var gh = publicKey.project(0);
var y = publicKey.project(1);

var r;
if (typeof random === "undefined") {

// Note that we choose r in R and not the ring of exponents of
// the group in which g is contained.
r = y.pGroup.pRing.randomElement(this.randomSource, this.statDist);
} else {
r = random;
}
return [r, gh.exp(r), y.exp(r)];
};

/**
* @description Completes the encryption of a message with the El
* Gamal cryptosystem.
* @param publicKey Public key of the form (g', y'), or ((g', h'), y')
* depending on if the standard or variant scheme is used.
* @param ruv Triple of the form [r, u, v] or [r, (u, a), v] as output
* by {@link verificatum.crypto.ElGamal.precomputeEncrypt}, depending on
* if the standard or variant scheme is used.
* @param message Message in G' to encrypt (must match group used in
* pre-computation).
* @return Ciphertext of the form (u, v * message) or ((u, a), v *
* message), depending on if the standard or variant scheme is used.
* @method
*/
ElGamal.prototype.completeEncrypt = function (publicKey, ruv, message) {
return publicKey.pGroup.prod([ruv[1], ruv[2].mul(message)]);
};

/**
* @description Encrypts a message with the El Gamal cryptosystem.
* @param publicKey Public key.
* @param message Message in G' to encrypt.
* @param random Randomness r in R' used for decryption. If this is
* empty, then it is generated.
* @return Ciphertext of the form output by {@link
* verificatum.crypto.ElGamal.completeEncrypt}.
* @method
*/
ElGamal.prototype.encrypt = function (publicKey, message, random) {
var ruv = this.precomputeEncrypt(publicKey, random);
return this.completeEncrypt(publicKey, ruv, message);
};

/**
* @description Decrypts an El Gamal ciphertext.
* @param privateKey Private key x' contained in R'.
* @param ciphertext Ciphertext (u, v) in G' x G', or ((u, a), v) in
* (G' x G') x G') to be decrypted, depending on if the standard or
* variant scheme is used.
* @return Plaintext computed as v / u^(x').
* @method
*/
ElGamal.prototype.decrypt = function (privateKey, ciphertext) {
var ua = ciphertext.project(0);
var v = ciphertext.project(1);
var u;

// Use ua directly for standard ciphertexts and only first
// component otherwise.
if (this.standard) {
u = ua;
} else {
u = ua.project(0);
}
return v.mul(u.exp(privateKey.neg()));
};

/**
* @description Widens a public key such that an element from a
* product group of the underlying group can be encrypted.
* @param publicKey Original public key.
* @param width Width of wider public key.
* @return Public key with the same key width, but with the given
* width.
*/
ElGamal.prototype.widePublicKey = function (publicKey, width) {
if (width > 1) {
var pkGroup = publicKey.pGroup;

// Widen second component.
var yGroup = pkGroup.project(1);
var y = publicKey.project(1);

var wyGroup = new verificatum.arithm.PPGroup(yGroup, width);
var wy = wyGroup.prod(y);

// Widen first component.
var ghGroup = pkGroup.project(0);
var gh = publicKey.project(0);

var wghGroup;
var wgh;

if (ghGroup.equals(yGroup)) {
wghGroup = wyGroup;
wgh = wghGroup.prod(gh);
} else {

// Extract components
var g = gh.project(0);
var h = gh.project(1);

// Widen each part.
var wg = wyGroup.prod(g);
var wh = wyGroup.prod(h);

// Combine the parts.
wghGroup = new verificatum.arithm.PPGroup(wyGroup, 2);
wgh = wghGroup.prod([wg, wh]);
}

var wpkGroup = new verificatum.arithm.PPGroup([wghGroup, wyGroup]);
return wpkGroup.prod([wgh, wy]);

} else {
return publicKey;
}
};

/**
* @description Widens a private key such that a ciphertext resulting
* from the encryption with the correspondingly widened public key can
* be decrypted.
* @param privateKey Original private key.
* @param width Width of wider public key.
* @return Public key with the same key width, but with the given
* width.
*/
ElGamal.prototype.widePrivateKey = function (privateKey, width) {
if (width > 1) {
var wskRing = new verificatum.arithm.PPRing(privateKey.pRing, width);
return wskRing.prod(privateKey);
} else {
return privateKey;
}
};

/**
* @description Estimates the running time of encryption in
* milliseconds.
* @param standard Indicates if the standard or variant scheme is
* used.
* @param pGroup Group over which the cryptosystem is defined.
* @param width Width of plaintexts.
* @param minSamples Minimum number of executions performed.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @return Estimated running time of encryption in milliseconds.
*/
ElGamal.benchEncryptPGroupWidth = function (standard, pGroup, width,
minSamples, randomSource, statDist) {
var eg = new ElGamal(standard, pGroup, randomSource, statDist);

var keys = eg.gen();
var wpk = eg.widePublicKey(keys[0], width);
var m = wpk.pGroup.project(1).getg();

var start = util.time_ms();
var j = 0;
while (j < minSamples) {
eg.encrypt(wpk, m);
j++;
}
return (util.time_ms() - start) / j;
};

/**
* @description Estimates the running time of encryption in
* milliseconds for various widths.
* @param standard Indicates if the standard or variant scheme is
* used.
* @param pGroup Group over which the cryptosystem is defined.
* @param maxWidth Maximal width of plaintexts.
* @param minSamples Minimum number of executions performed.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @return Array of estimated running times of encryption in
* milliseconds.
*/
ElGamal.benchEncryptPGroup = function (standard, pGroup, maxWidth,
minSamples, randomSource, statDist) {
var results = [];
for (var i = 1; i <= maxWidth; i++) {
var t = ElGamal.benchEncryptPGroupWidth(standard, pGroup, i,
minSamples, randomSource,
statDist);
results.push(t);
}
return results;
};

/**
* @description Estimates the running time of encryption in
* milliseconds for various groups and widths.
* @param standard Indicates if the standard or variant scheme is
* used.
* @param pGroups Groups over which the cryptosystem is defined.
* @param maxWidth Maximal width of plaintexts.
* @param minSamples Minimum number of executions performed.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @return Array or arrays of estimated running time of encryption in
* milliseconds.
*/
ElGamal.benchEncrypt = function (standard, pGroups, maxWidth,
minSamples, randomSource, statDist) {
var results = [];
for (var i = 0; i < pGroups.length; i++) {
results[i] = ElGamal.benchEncryptPGroup(standard, pGroups[i], maxWidth,
minSamples, randomSource,
statDist);
}
return results;
};


// ######################################################################
// ################### ElGamalZKPoKAdapter ##############################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
* @description Adapter for {@link verificatum.crypto.ElGamalZKPoK}
* that creates {@link verificatum.crypto.ZKPoK} that imposes
* restrictions on plaintexts and ciphertexts.
* @abstract
* @class
* @memberof verificatum.crypto
*/
function ElGamalZKPoKAdapter() {};
ElGamalZKPoKAdapter.prototype = Object.create(Object.prototype);
ElGamalZKPoKAdapter.prototype.constructor = ElGamalZKPoKAdapter;

/**
* @description Generates a {@link verificatum.crypto.ZKPoK} that
* imposes restrictions on ciphertexts.
* @param publicKey El Gamal public key.
* @return Instance of {@link verificatum.crypto.ZKPoK}.
* @method
*/
ElGamalZKPoKAdapter.prototype.getZKPoK = function (publicKey) {
throw new Error("Abstract method!");
};
/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */


// ######################################################################
// ################### ElGamalZKPoK #####################################
// ######################################################################

/**
* @description Generalized El Gamal cryptosystem with parameterized
* zero-knowledge proof of knowledge. This supports wider keys as
* explained in {@link verificatum.crypto.ElGamal}.
*
* <p>
*
* Restrictions on the ciphertexts and encrypted plaintexts are
* readily expressed by forming an application specific ZKPoK and
* setting the adapter variable.
*
* @param standard Determines if the standard or variant El Gamal
* cryptosystem is used.
* @param pGroup Group G over which the cryptosystem is defined. This
* can be a product group if the key width is greater than one.
* @param adapter Adapter for instantiating ZKPoKs.
* @param hashfunction Hash function used to implement the Fiat-Shamir
* heuristic in ZKPoKs.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @class
* @memberof verificatum.crypto
*/
function ElGamalZKPoK(standard, pGroup, adapter, hashfunction,
randomSource, statDist) {
this.eg = new ElGamal(standard, pGroup, randomSource, statDist);
this.adapter = adapter;
this.hashfunction = hashfunction;
};
ElGamalZKPoK.prototype = Object.create(Object.prototype);
ElGamalZKPoK.prototype.constructor = ElGamalZKPoK;

/**
* @description Generates a key pair over the given group.
* @return Pair [pk, sk] such that pk is a public key in G x G or in
* (G x G) x G depending on if the standard or variant scheme is used,
* and sk is the corresponding private key contained in R.
* @method
*/
ElGamalZKPoK.prototype.gen = function () {
return this.eg.gen();
};

/**
* @description Pre-computation for encrypting a message using {@link
* verificatum.crypto.ElGamalZKPoK.completeEncrypt}.
* @param publicKey Public key output by {@link
* verificatum.crypto.ElGamalZKPoK.gen}.
* @return A pair [e, z], where e are the values pre-computed by
* {@link verificatum.crypto.ElGamal.precomputeEncrypt} and z are the
* values pre-computed by the subclass of {@link
* verificatum.crypto.ZKPoK.precompute} used.
* @method
*/
ElGamalZKPoK.prototype.precomputeEncrypt = function (publicKey) {
var ruv = this.eg.precomputeEncrypt(publicKey);
var zkpok = this.adapter.getZKPoK(publicKey);
var pre = zkpok.precompute(this.eg.randomSource, this.eg.statDist);
return [ruv, pre];
};

/**
* @description Completes the encryption.
* @param label Label used for encryption.
* @param publicKey Public key.
* @param precomputed Output from {@link
* verificatum.crypto.ElGamalZKPoK.precomputeEncrypt}.
* @param message Message in G to encrypt.
* @return Ciphertext in the form of a byte tree.
* @method
*/
ElGamalZKPoK.prototype.completeEncrypt = function (label,
publicKey,
precomputed,
message) {
var egc = this.eg.completeEncrypt(publicKey, precomputed[0], message);
var zkpok = this.adapter.getZKPoK(publicKey);
var proof = zkpok.completeProof(precomputed[1],
label,
egc, precomputed[0][0],
this.hashfunction,
this.eg.randomSource,
this.eg.statDist);
return new eio.ByteTree([egc.toByteTree(), new eio.ByteTree(proof)]);
};

/**
* @description Encrypts a message.
* @param label Label used for encryption.
* @param publicKey Public key.
* @param message Message in G' to encrypt.
* @return Ciphertext of the form of a byte tree.
* @method
*/
ElGamalZKPoK.prototype.encrypt = function (label, publicKey, message) {
var precomputed = this.precomputeEncrypt(publicKey);
return this.completeEncrypt(label, publicKey, precomputed, message);
};

/**
* @description Decrypts an El Gamal ciphertext.
* @param label Label used for decryption.
* @param privateKey Private key in R'.
* @param ciphertext Ciphertext in the form of a byte tree.
* @return Plaintext or null to indicate that the ciphertext was
* invalid.
* @method
*/
ElGamalZKPoK.prototype.decrypt = function (label, publicKey, privateKey,
ciphertext) {
if (ciphertext.isLeaf() ||
ciphertext.value.length !== 2 ||
!ciphertext.value[1].isLeaf()) {
return null;
}
var ciphertextElement;
try {
ciphertextElement = publicKey.pGroup.toElement(ciphertext.value[0]);
} catch (err) {
return null;
}
var proof = ciphertext.value[1].value;

var zkpok = this.adapter.getZKPoK(publicKey);
var verdict =
zkpok.verify(label, ciphertextElement, this.hashfunction, proof);
if (verdict) {
return this.eg.decrypt(privateKey, ciphertextElement);
} else {
return null;
}
};

ElGamalZKPoK.prototype.widePublicKey = function (publicKey, width) {
return this.eg.widePublicKey(publicKey, width);
};

ElGamalZKPoK.prototype.widePrivateKey = function (privateKey, width) {
return this.eg.widePrivateKey(privateKey, width);
};


// ######################################################################
// ################### ZKPoKWriteIn #####################################
// ######################################################################

/**
* @description Zero-knowledge proof needed to implement the Naor-Yung
* cryptosystem.
* @class
* @extends verificatum.arithm.ZKPoK
* @memberof verificatum.crypto
*/
function ZKPoKWriteIn(publicKey) {
var domain = publicKey.project(1).pGroup.pRing;
var basis = publicKey.project(0);
var expHom = new arithm.ExpHom(domain, basis);
this.sp = new SchnorrProof(expHom);
};
ZKPoKWriteIn.prototype = Object.create(ZKPoK.prototype);
ZKPoKWriteIn.prototype.constructor = ZKPoKWriteIn;

ZKPoKWriteIn.prototype.precompute = function (randomSource, statDist) {
return this.sp.precompute(randomSource, statDist);
};

/**
* @description Combines an arbitrary label with parts of the instance
* not included as input by the ZKPoK itself.
* @param label Label in the form of a byte array or byte tree.
* @param instance Complete instance.
* @return Combined label.
*/
ZKPoKWriteIn.makeLabel = function (label, instance) {
var lbt = eio.ByteTree.asByteTree(label);
var ebt = instance.project(1).toByteTree();
return new eio.ByteTree([lbt, ebt]);
};

ZKPoKWriteIn.prototype.completeProof = function (precomputed,
label, instance, witness,
hashfunction,
randomSource, statDist) {
label = ZKPoKWriteIn.makeLabel(label, instance);
return this.sp.completeProof(precomputed, label,
instance.project(0), witness,
hashfunction, randomSource, statDist);
};

ZKPoKWriteIn.prototype.verify = function (label, instance, hashfunction, proof) {
label = ZKPoKWriteIn.makeLabel(label, instance);
return this.sp.verify(label, instance.project(0), hashfunction, proof);
};


// ######################################################################
// ################### ZKPoKWriteInAdapter ##############################
// ######################################################################

/**
* @description Adapter for {@link verificatum.crypto.ZKPoKWriteIn}.
* @class
* @extends verificatum.arithm.ElGamalZKPoKAdapter
* @memberof verificatum.crypto
*/
function ZKPoKWriteInAdapter() {};
ZKPoKWriteInAdapter.prototype = Object.create(ElGamalZKPoKAdapter.prototype);
ZKPoKWriteInAdapter.prototype.constructor = ZKPoKWriteInAdapter;

ZKPoKWriteInAdapter.prototype.getZKPoK = function (publicKey) {
return new ZKPoKWriteIn(publicKey);
};


// ######################################################################
// ################### ElGamalZKPoKWriteIn ##############################
// ######################################################################

/**
* @description Generalized Naor-Yung cryptosystem, i.e., a
* generalized El Gamal with zero-knowledge proof of knowledge of the
* plaintext without any restrictions on the plaintext.
* @param standard Determines if the standard or variant El Gamal
* cryptosystem is used.
* @param pGroup Group G over which the cryptosystem is defined.
* @param hashfunction Hash function used to implement the Fiat-Shamir
* heuristic in ZKPoKs.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @class
* @memberof verificatum.crypto
*/
function ElGamalZKPoKWriteIn(standard, pGroup, hashfunction, randomSource,
statDist) {
ElGamalZKPoK.call(this, standard, pGroup, new ZKPoKWriteInAdapter(),
hashfunction, randomSource, statDist);
};
ElGamalZKPoKWriteIn.prototype = Object.create(ElGamalZKPoK.prototype);
ElGamalZKPoKWriteIn.prototype.constructor = ElGamalZKPoKWriteIn;

/**
* @description Estimates the running time of encryption in
* milliseconds.
* @param standard Indicates if the standard or variant scheme is
* used.
* @param pGroup Group over which the cryptosystem is defined.
* @param hashfunction Hash function used for Fiat-Shamir heuristic.
* @param width Width of plaintexts.
* @param minSamples Minimum number of executions performed.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @return Estimated running time of encryption in milliseconds.
*/
ElGamalZKPoKWriteIn.benchEncryptPGroupWidth = function (standard,
pGroup,
hashfunction,
width,
minSamples,
randomSource,
statDist) {
var eg = new ElGamalZKPoKWriteIn(standard, pGroup, hashfunction,
randomSource, statDist);

var keys = eg.gen();
var wpk = eg.widePublicKey(keys[0], width);
var m = wpk.pGroup.project(1).getg();
var label = randomSource.getBytes(10);

var start = util.time_ms();
var j = 0;
while (j < minSamples) {
eg.encrypt(label, wpk, m);
j++;
}
return (util.time_ms() - start) / j;
};

/**
* @description Estimates the running time of encryption in
* milliseconds for various widths.
* @param standard Indicates if the standard or variant scheme is
* used.
* @param pGroup Group over which the cryptosystem is defined.
* @param hashfunction Hash function used for Fiat-Shamir heuristic.
* @param maxWidth Maximal width of plaintexts.
* @param minSamples Minimum number of executions performed.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @return Array of estimated running times of encryption in
* milliseconds.
*/
ElGamalZKPoKWriteIn.benchEncryptPGroup = function (standard,
pGroup,
hashfunction,
maxWidth,
minSamples,
randomSource,
statDist) {
var results = [];
for (var i = 1; i <= maxWidth; i++) {
var t = ElGamalZKPoKWriteIn.benchEncryptPGroupWidth(standard,
pGroup,
hashfunction,
i,
minSamples,
randomSource,
statDist);
results.push(t);
}
return results;
};

/**
* @description Estimates the running time of encryption in
* milliseconds for various groups and widths.
* @param standard Indicates if the standard or variant scheme is
* used.
* @param pGroups Groups over which the cryptosystem is defined.
* @param hashfunction Hash function used for Fiat-Shamir heuristic.
* @param maxWidth Maximal width of plaintexts.
* @param minSamples Minimum number of executions performed.
* @param randomSource Source of randomness.
* @param statDist Statistical distance from the uniform distribution
* assuming that the output of the instance of the random source is
* perfect.
* @return Array or arrays of estimated running time of encryption in
* milliseconds.
*/
ElGamalZKPoKWriteIn.benchEncrypt = function (standard, pGroups,
hashfunction, maxWidth,
minSamples, randomSource,
statDist) {
var results = [];
for (var i = 0; i < pGroups.length; i++) {
results[i] = ElGamalZKPoKWriteIn.benchEncryptPGroup(standard,
pGroups[i],
hashfunction,
maxWidth,
minSamples,
randomSource,
statDist);
}
return results;
};

return {
"sha256": sha256,
"getStatDist": getStatDist,
"RandomSource": RandomSource,
"RandomDevice": RandomDevice,
"SHA256PRG": SHA256PRG,
"SigmaProof": SigmaProof,
"SigmaProofPara": SigmaProofPara,
"SigmaProofAnd": SigmaProofAnd,
"SigmaProofOr": SigmaProofOr,
"SchnorrProof": SchnorrProof,
"ElGamal": ElGamal,
"ElGamalZKPoKAdapter": ElGamalZKPoKAdapter,
"ElGamalZKPoK": ElGamalZKPoK,
"ZKPoKWriteIn": ZKPoKWriteIn,
"ZKPoKWriteInAdapter": ZKPoKWriteInAdapter,
"ElGamalZKPoKWriteIn": ElGamalZKPoKWriteIn
};
})();


// ######################################################################
// ################### Javascript Verificatum Client ####################
// ######################################################################
//
// Javascript Verificatum client library for implementing clients. We
// refer the reader to the accompanying README file for more
// information.

/**
* @description Provide html formatting functions for benchmarks.
* @namespace benchmark
*/
var benchmark = (function () {

/**
* @description Returns a string representation of the today's date.
* @return Today's date.
* @function today
* @memberof verificatum.benchmark
*/
var today = function () {
var today = new Date();
var dd = today.getDate();
var mm = today.getMonth() + 1;
var yyyy = today.getFullYear();

if (dd < 10) {
dd = "0" + dd;
}

if (mm < 10) {
mm = "0" + mm;
}

return yyyy + "-" + mm + "-" + dd;
};

/* jshint -W117 */ /* Ignore undefinitions. */
/* eslint-disable spaced-comment */
/* eslint-disable no-implicit-coercion */
/* eslint-disable no-undef */
/* eslint-disable no-extra-boolean-cast */
/**
* @description Makes a decent attempt to identify the browser
* used. This is a horrible hack that probes properties that are not
* stable with versions. Do not use this for anything important.
* @return Browser string.
* @function browser
* @memberof verificatum.benchmark
*/
var browser = function () {

if (!!window.opr && !!opr.addons || !!window.opera ||
navigator.userAgent.indexOf(" OPR/") >= 0) {
return "Opera 8.0+";
} else if (typeof InstallTrigger !== "undefined") {
return "Firefox 1.0+";
} else if (Object.prototype.toString.call(window.HTMLElement).
indexOf("Constructor") > 0) {
return "Safari 3+";
} else if (/*@cc_on!@*/false || !!document.documentMode) {
return "Internet Explorer 6-11";
} else if (!!window.StyleMedia) {
return "Edge 20+";
} else if (!!window.chrome && !!window.chrome.webstore) {
return "Chrome 1+";
} else {
return "Unable to detect";
}
};
/* jshint +W117 */ /* Stop ignoring undefinitions. */
/* eslint-enable spaced-comment */
/* eslint-enable no-implicit-coercion */
/* eslint-enable no-undef */
/* eslint-enable no-extra-boolean-cast */

/**
* @description Formats a list of benchmark results.
* @param pGroupNames List of names of groups.
* @param restuls List of timings.
* @return HTML code for output.
* @function grpTable
* @memberof verificatum.benchmark
*/
var grpTable = function (pGroupNames, results) {
var s = "<table>\n";
s += "<tr>" +
"<th>Group</th>" +
"<th>ms / exp</th>" +
"</tr>\n";
for (var i = 0; i < results.length; i++) {
s += "<tr>";
s += "<td>" + pGroupNames[i] + "</td>";
s += "<td style=\"text-align:right\">" + results[i].toFixed(1) + "</td>";
s += "</tr>\n";
}
s += "</table>";
return s;
};

var grpIntHeader = function (header, indices) {
var s = "<tr>\n<th>Group \\ " + header + "</th>\n";
for (var i = 0; i < indices.length; i++) {
s += "<th>" + indices[i] + "</th>\n";
}
return s + "</tr><h>\n";
};

var grpIntRow = function (pGroupName, results) {
var s = "<tr>\n<td>" + pGroupName + "</td>\n";
for (var i = 0; i < results.length; i++) {
s += "<td style=\"text-align:right\">" + results[i].toFixed(1) + "</td>\n";
}
return s + "</tr>\n";
};

var grpIntTable = function (header, indices, pGroupNames, results) {
var s = "<table>\n";
s += grpIntHeader(header, indices);
for (var i = 0; i < results.length; i++) {
s += grpIntRow(pGroupNames[i], results[i]);
}
s += "</table>";
return s;
};

return {
"today": today,
"browser": browser,
"grpTable": grpTable,
"grpIntTable": grpIntTable
};
})();

return {
"version": "1.1.1",

"util": util,
"eio": eio,
"arithm": arithm,
"crypto": crypto,
"benchmark": benchmark
};
})();

// drb
module.exports = {
    arithm: verificatum.arithm,
    crypto: verificatum.crypto,
    util: verificatum.util,
    eio: verificatum.eio
}
// drb