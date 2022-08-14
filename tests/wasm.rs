#![allow(unused_variables)]

const PLAINTEXT_VALUES: [&str; 4] = [
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    "hello world",
    "#Üoaj23hrutb/",
    "foo\nbar",
];

const CIPHERTEXT_DEFAULT_KEY: [&str; 4] = [
    "-AQ==/X2ea4Ow2MggZdA8s6p/2QBLG+M=vLGxsHcul1CSXvw4t3inudMcRdCCUdVu9pXPIN+Zfm4tc8QR38brRJ2HeYVbtmUKIxf92cw+Ik451GyzVAWLzy3Lan5oaPJSodAPyGjQ5w1kaK4add6bizt4/OyaxJojknOhYvRdpmOkrDK08Jvtdw==",
    "-AQ==Kq5sNclPz7QV2+lfQIuc6R7oRu0=hIhc0Phi+RYYxgpkbZ3rZA==",
    "-AQ==J9HWuJT9IjpD7xObbFb0wYdr3G8=7XxDjkQ2kMI7I1Lh1W5njg==",
    "-AQ==JDMiu5l+hyLHa3FR3/rag8K1G9A=Knwzvszo9U7EZlWW0oLibA==",
];

const CUSTOM_KEY: &str = "!._$%&/()=123456";
const CIPHERTEXT_CUSTOM_KEY: [&str; 4] = [
    "-AQ==/X2ea4Ow2MggZdA8s6p/2QBLG+M=ekyP8N7sMUaLeYOH8VGWWMQaEHlTqWjSfq68TgJY3BWJc7O0E4GcEeZvYOxa8lmkaUDjqnbG5CXWKBkCkUb+m1Z4kHs7DOkhBZ74DvKRs4DpUhss+rRaSCX73zwCeucaKAJinbHwAnmbDoxBrAzaFg==",
    "-AQ==Kq5sNclPz7QV2+lfQIuc6R7oRu0=GT5qaYuXL6yWIY+AERV2QA==",
    "-AQ==J9HWuJT9IjpD7xObbFb0wYdr3G8=GH9ft/BbDWREyM5QtVanzA==",
    "-AQ==JDMiu5l+hyLHa3FR3/rag8K1G9A=kFNF6riNzVd2V4N/JyXCnA==",
];

fn main() {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_encryption() {
        let len = PLAINTEXT_VALUES.len();
        for i in 0..len {
            assert_eq!(
                panos_crypto_tools::panos_encrypt("", PLAINTEXT_VALUES[i]),
                CIPHERTEXT_DEFAULT_KEY[i],
            );
            assert_eq!(
                panos_crypto_tools::panos_encrypt(CUSTOM_KEY, PLAINTEXT_VALUES[i]),
                CIPHERTEXT_CUSTOM_KEY[i],
            );
        }
    }

    #[wasm_bindgen_test]
    fn test_decryption() {
        let len = PLAINTEXT_VALUES.len();
        for i in 0..len {
            assert_eq!(
                panos_crypto_tools::panos_decrypt("", CIPHERTEXT_DEFAULT_KEY[i]),
                PLAINTEXT_VALUES[i],
            );
            assert_eq!(
                panos_crypto_tools::panos_decrypt(CUSTOM_KEY, CIPHERTEXT_CUSTOM_KEY[i]),
                PLAINTEXT_VALUES[i],
            );
        }
    }
}
