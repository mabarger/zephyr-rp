#!/usr/bin/env python3
#
# Copyright (c) 2023 Maximilian Barger
#
# SPDX-License-Identifier: Apache-2.0

"""This script will parse an attestation key stored in attestation_keys and
generate a C file containing a loader for it using immediate values
"""

import os
import sys

key_path      = "attestation_keys/dilithium2.key"
template_path = "sprav_template.c"
out_path      = "sprav.c"

placeholder   = "{LOAD_ATTESTATION_KEY_PLACEHOLDER}"

def gen_loader_instructions(raw_key):
    loader_instructions = ""
    words = list()
    for idx in range(0, len(raw_key), 8):
        word = raw_key[idx:idx+8]
        word = "".join(reversed([word[i:i+2] for i in range(0, len(word), 2)]))
        if len(word) == 8:
            words.append(word)

    offs = 0
    for word in words:
        loader_instructions += f"STORE_WORD_IMMEDIATE(sprav_attestation_key+{offs:#0{6}x}, 0x{word});\n"
        offs += 4

    return loader_instructions

def main():
    template = ""
    raw_key = ""

    if len(sys.argv) >= 2:
        os.chdir(sys.argv[1])

    # Read in the template file
    with open(template_path, 'r') as file:
        template = file.read()

    # Read in the key
    with open(key_path, 'r') as file:
        key = file.read()

    # Generate loader instructions
    loader_instructions = gen_loader_instructions(key)

    # Replace placeholder in template with loader instructions
    output = template.replace(placeholder, loader_instructions)

    # Write generated file
    with open(out_path, 'w') as file:
        file.write(output)

if __name__ == '__main__':
    main()
