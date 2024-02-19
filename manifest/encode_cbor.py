# This script reads in a CBOR input from a `manifest.in.cbor`` file and
# generates a serialised stream from it and saves this in a `manifest.out.cbor`.
# The serialised stream is to be used by spdm-utils.
import cbor2

try:
    # Fetch all the bytes from our manifest file
    with open('manifest.in.cbor', 'r') as file:
        # Read all the bytes
        input_cbor = file.read()
except FileNotFoundError:
    print("Error: manifest.in.cbor not found.")
    exit(1)
except Exception as e:
    print(f"Error reading manifest.in.cbor: {e}")
    exit(2)

try:
    # Serialize
    encoded_data =  cbor2.dumps(input_cbor, string_referencing=True, canonical=True)
except Exception as e:
    print(f"Error encoding CBOR: {e}")
    exit(1)

print(f"Encoded CBOR Hex Stream")
print(encoded_data.hex())

try:
    decoded_bytes = cbor2.loads(encoded_data)
except Exception as e:
    print(f"Error decoding CBOR: {e}")
    exit(1)

# Make sure we can decode back to the original
assert input_cbor == decoded_bytes

try:
    # Create/overwrite (if existing) a file and write the encoded
    # cbor stream to it.
    with open('manifest.out.cbor', 'wb') as file:
        file.write(encoded_data)

except Exception as e:
    print(f"Error writing encoded cbor hex stream to file: {e}")
    exit(1)

print("CBOR Encoded byte stream written to manifest.out.cbor")

