from md5 import md5

outerpad = [0x5c] * 64
innerpad = [0x36] * 64


#hmac<K>(text) = (H_func(K xor outerpad)+ H_func((K xor ipad) + text))
def hmac_solve(key, message, size_of_block=64):
    if len(key) > size_of_block:
        key = md5(key).zip_convert()

    if(len(key) < size_of_block):
        for i in range(size_of_block - len(key)):
            key += b'\0'

    i_key_pad = ''.join([chr(x ^ y) for x, y in zip(key, outerpad)])

    o_key_pad = ''.join([chr(x ^ y) for x, y in zip(key, innerpad)])

    k_opad_data = (i_key_pad + message)
    hashable = (o_key_pad + k_opad_data)
    return md5(hashable).zip_convert()

#hmac<K>(text) = (H_func(K xor outerpad)+ H_func((K xor ipad) + text))
if __name__ == '__main__':
    key = 'key_dgdz;kjzjd;flddsdddddddddddfdsdfddddddddddsssssssssssssfksdfgdsfg_hello_world'
    res1 = (hmac_solve(key, message='Hello woreld'))
    print("result: {}".format(res1))

    res2 = (hmac_solve(key, message='Hello woreld'))
    print("result: {}".format(res2))

    print(res1==res2)