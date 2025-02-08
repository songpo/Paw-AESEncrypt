import {
    registerDynamicValueClass,
    InputField
} from './__mocks__/Shims'

import CryptoJS from 'crypto-js'

@registerDynamicValueClass
export default class DynamicValue {
    // TODO update static information with correct ones
    // Organisation
    static organisation = 'luckymarmot'
    static repository = 'Paw-AESEncryptDynamicValue'

    // Generator
    static identifier = 'com.luckymarmot.PawExtensions.AESEncryptDynamicValue'
    static title = 'AES Encrypt'

    static help = 'https://github.com/luckymarmot/Paw-AESEncryptDynamicValue'

    static inputs = [
        new InputField(
            'message',
            'Message',
            'SecureValue',
            {
                persisted: true,
                placeholder: 'the message to encrypt'
            }
        ),
        new InputField(
            'msgEnc',
            'Message Encoding',
            'Select',
            {
                persisted: true,
                choices: {
                    Hex: 'Hex',
                    Base64: 'Base 64',
                    Utf8: 'UTF 8 (default)',
                    Utf16: 'UTF 16',
                    Latin1: 'Latin1'
                },
                defaultValue: 'Utf8'
            }
        ),
        new InputField(
            'key',
            'Secret Key',
            'SecureValue',
            {
                persisted: true,
                placeholder: 'secret key'
            }
        ),
        new InputField(
            'keyEnc',
            'Key Encoding',
            'Select',
            {
                persisted: true,
                choices: {
                    Hex: 'Hex',
                    Base64: 'Base 64',
                    Utf8: 'UTF 8 (default)',
                    Utf16: 'UTF 16',
                    Latin1: 'Latin1'
                },
                defaultValue: 'Hex'
            }
        ),
        new InputField(
            'iv',
            'Initialization Vector',
            'SecureValue',
            {
                persisted: true
            }
        ),
        new InputField(
            'ivEnc',
            'IV Encoding',
            'Select',
            {
                persisted: true,
                choices: {
                    Hex: 'Hex (default)',
                    Base64: 'Base 64',
                    Utf8: 'UTF 8',
                    Utf16: 'UTF 16',
                    Latin1: 'Latin1'
                },
                defaultValue: 'Hex'
            }
        ),
        new InputField(
            'mode',
            'Mode',
            'Select',
            {
                persisted: true,
                choices: {
                    CBC: 'Chipher Block Chain (default)',
                    CFB: 'Cipher Feedback',
                    CTR: 'Counter',
                    CTRGladman: 'Counter (Gladman)',
                    OFB: 'Output Feedback',
                    ECB: 'Electronic Codebook'
                },
                defaultValue: 'CBC'
            }
        ),
        new InputField(
            'pad',
            'Padding',
            'Select',
            {
                persisted: true,
                choices: {
                    Pkcs7: 'PKCS7 (default)',
                    Ansix923: 'ANSI X.923',
                    Iso10126: 'ISO 10126',
                    Iso97971: 'ISO/IEC 9797-1',
                    ZeroPadding: 'Zero Padding',
                    NoPadding: 'No Padding'
                },
                defaultValue: 'Pkcs7'
            }
        )
    ]

    // args: context
    evaluate() {
        if (
            !this.message ||
            !this.msgEnc ||
            !this.key ||
            !this.keyEnc ||
            !this.pad ||
            !this.mode
        ) {
            return null
        }

        const msgEnc = this.msgEnc || 'Utf8'
        const keyEnc = this.keyEnc || 'Utf8'
        const padding = this.pad || 'Pkcs7'
        const mode = this.mode || 'CBC'

        const message = CryptoJS.enc[msgEnc].parse(this.message)
        const key = CryptoJS.enc[keyEnc].parse(this.key)

        const options = {}
        let hasOptions = false

        if (this.iv) {
            let iv = this.iv
            if (this.ivEnc) {
                iv = CryptoJS.enc[this.ivEnc].parse(this.iv)
            }
            options.iv = iv
            hasOptions = true
        }

        if (this.pad && this.pad !== 'Pkcs7') {
            options.padding = CryptoJS.pad[padding]
            hasOptions = true
        }

        if (this.mode && this.mode !== 'CBC') {
            options.mode = CryptoJS.mode[mode]
            hasOptions = true
        }

        let encrypted = null
        try {
            if (hasOptions) {
                encrypted = CryptoJS.AES.encrypt(
                    message,
                    key,
                    options
                )
            }
            else {
                encrypted = CryptoJS.AES.encrypt(
                    message,
                    key
                )
            }

            return encrypted.toString()
        }
        catch (e) {
            /* eslint-disable no-console */
            console.log('warn --- error in AES encrypt', e)
            /* eslint-enable no-console */
            return null
        }
    }
}
