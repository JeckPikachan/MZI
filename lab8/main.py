import PIL
import numpy as np
from skimage import io
from skimage.util import view_as_blocks
from scipy.fftpack import dct, idct
from PIL import ImageFilter, Image

u1, v1 = 4, 5
u2, v2 = 5, 4
n = 8
P = 25

def nsplit(s, n):  # Split a list into sublists of size "n"
    return [s[k:k + n] for k in range(0, len(s), n)]


def binvalue(val, bitsize):  # Return the binary value as a string of the given size
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise Exception("binary value larger than the expected size")
    while len(binval) < bitsize:
        binval = "0" + binval  # Add as many 0 as needed to get the wanted size
    return binval


def string_to_bit_array(raw_text):  # Convert a string into a list of bits
    array = list()
    for char in raw_text:
        binval = binvalue(char, 8)  # Get the char value on one byte
        array.extend([int(x) for x in list(binval)])  # Add the bits to the final list
    return array


def bit_array_to_string(array):  # Recreate the string from the bit array
    res = ''.join([chr(int(y, 2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in nsplit(array, 8)]])
    return res


def double_to_byte(arr):
    return np.uint8(np.round(np.clip(arr, 0, 255), 0))


def increment_abs(x):
    return x + 1 if x >= 0 else x - 1


def decrement_abs(x):
    if np.abs(x) <= 1:
        return 0
    else:
        return x - 1 if x >= 0 else x + 1


# Functions to change the DCT coefficients
def abs_diff_coefs(transform):
    return abs(transform[u1, v1]) - abs(transform[u2, v2])


def valid_coefficients(transform, bit, threshold):
    difference = abs_diff_coefs(transform)
    if (bit == 0) and (difference > threshold):
        return True
    elif (bit == 1) and (difference < -threshold):
        return True
    else:
        return False


def change_coefficients(transform, bit):
    coefs = transform.copy()
    if bit == 0:
        coefs[u1, v1] = increment_abs(coefs[u1, v1])
        coefs[u2, v2] = decrement_abs(coefs[u2, v2])
    elif bit == 1:
        coefs[u1, v1] = decrement_abs(coefs[u1, v1])
        coefs[u2, v2] = increment_abs(coefs[u2, v2])
    return coefs


# Inserting a message into an image
def embed_bit(block, bit):
    patch = block.copy()
    coefficients = dct(dct(patch, axis=0), axis=1)
    while not valid_coefficients(coefficients, bit, P) or (bit != retrieve_bit(patch)):
        coefficients = change_coefficients(coefficients, bit)
        # print(coefficients[u1, v1], coefficients[u2, v2])
        # discrete cosine transform
        patch = double_to_byte(idct(idct(coefficients, axis=0), axis=1) / (2 * n) ** 2)
    return patch


def embed_message(original, msg):
    changed = original.copy()
    blue = changed[:, :, 2]
    width, height = np.shape(blue)
    width -= width % n
    height -= height % n
    blue = blue[:width, :height]
    # new_width, new_height = np.shape(blue)
    blocks = view_as_blocks(blue, block_shape=(n, n))
    h = blocks.shape[1]
    for index, bit in enumerate(msg):
        # print('index=%d, bit=%d' % (index, bit))
        i = index // h
        j = index % h
        block = blocks[i, j]
        blue[i * n: (i + 1) * n, j * n: (j + 1) * n] = embed_bit(block, bit)
    changed[:width, :height, 2] = blue
    return changed


# Extracting the hidden message
def retrieve_bit(block):
    transform = dct(dct(block, axis=0), axis=1)
    return 0 if abs_diff_coefs(transform) > 0 else 1


def retrieve_message(img, length):
    img = img[:, :, 2]
    width, height = np.shape(img)
    width -= width % n
    height -= height % n
    img = img[:width, :height]
    blocks = view_as_blocks(img, block_shape=(n, n))
    h = blocks.shape[1]
    return [retrieve_bit(blocks[index // h, index % h]) for index in range(length)]


def steganography_encrypt(data_in, image_in, image_out):
    image_in = io.imread(image_in)
    data_in = string_to_bit_array(data_in)
    data_in_len = len(data_in)
    image_out = embed_message(image_in, data_in)
    return image_out, data_in_len


def steganography_decrypt(text_length, image_out):
    image_out = io.imread(image_out)
    out_message = retrieve_message(image_out, text_length)
    out_message = bit_array_to_string(out_message)
    return out_message


def main():
    data_in = "data_in.txt"
    data_out = "data_out.txt"
    image_in = "image_in.JPG"
    image_out = "image_out.JPG"

    # part 1 - encoding
    with open(data_in, 'r+') as f:
        input_text = f.read()
    length_input_text = len(input_text)

    print('Input data: ', input_text)
    print('Input image file: ', image_in)
    image_out_file, data_in_len = steganography_encrypt(input_text, image_in, image_out)

    io.imsave(image_out, image_out_file)

    image = Image.open('image_in.jpg')
    im1 = image.filter(ImageFilter.BLUR)
    im1.show()
    print(im1)


if __name__ == '__main__':
    main()
