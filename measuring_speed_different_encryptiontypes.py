import time
import hmac
import hashlib
import rsa
import ecdsa

# Define constants
MESSAGE = b'Measuring the speed difference between different encryption types'  # 메시지 데이터
ITERATIONS = 1000  # 반복 횟수
HASH_SIZE = 64  # 512 비트 = 64 바이트 (사용되지 않음, 설명용)

# HMAC 테스트 함수
def hmac_test():
    key = b'secret_key'  # HMAC에 사용할 비밀 키
    h = hmac.new(key, digestmod=hashlib.sha512)  # HMAC 객체 생성

    # 서명 생성 시간 측정
    start_time = time.time()  # 시작 시간 기록
    for _ in range(ITERATIONS):
        h.update(MESSAGE)  # 메시지 업데이트
        signature = h.digest()  # 서명 생성
    signing_time = (time.time() - start_time) / ITERATIONS  # 평균 서명 생성 시간 계산

    # 서명 검증 시간 측정
    start_time = time.time()  # 시작 시간 기록
    for _ in range(ITERATIONS):
        h = hmac.new(key, MESSAGE, hashlib.sha512)  # 새로운 HMAC 객체 생성
        hmac.compare_digest(h.digest(), signature)  # 서명 검증
    verification_time = (time.time() - start_time) / ITERATIONS  # 평균 서명 검증 시간 계산

    return signing_time, verification_time  # 서명 생성 및 검증 시간 반환

# RSA 테스트 함수
def rsa_test():
    (pub_key, priv_key) = rsa.newkeys(4096)  # RSA 공개키 및 개인키 생성

    # 서명 생성 시간 측정
    start_time = time.time()  # 시작 시간 기록
    for _ in range(ITERATIONS):
        signature = rsa.sign(MESSAGE, priv_key, 'SHA-512')  # 메시지 서명 생성
    signing_time = (time.time() - start_time) / ITERATIONS  # 평균 서명 생성 시간 계산

    # 서명 검증 시간 측정
    start_time = time.time()  # 시작 시간 기록
    for _ in range(ITERATIONS):
        rsa.verify(MESSAGE, signature, pub_key)  # 서명 검증
    verification_time = (time.time() - start_time) / ITERATIONS  # 평균 서명 검증 시간 계산

    return signing_time, verification_time  # 서명 생성 및 검증 시간 반환

# ECDSA 테스트 함수
def ecdsa_test():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST521p)  # ECDSA 서명키 생성
    vk = sk.verifying_key  # ECDSA 검증키 추출

    # 서명 생성 시간 측정
    start_time = time.time()  # 시작 시간 기록
    for _ in range(ITERATIONS):
        signature = sk.sign(MESSAGE, hashfunc=hashlib.sha512)  # 메시지 서명 생성
    signing_time = (time.time() - start_time) / ITERATIONS  # 평균 서명 생성 시간 계산

    # 서명 검증 시간 측정
    start_time = time.time()  # 시작 시간 기록
    for _ in range(ITERATIONS):
        vk.verify(signature, MESSAGE, hashfunc=hashlib.sha512)  # 서명 검증
    verification_time = (time.time() - start_time) / ITERATIONS  # 평균 서명 검증 시간 계산

    return signing_time, verification_time  # 서명 생성 및 검증 시간 반환

# 테스트 실행
hmac_sign_time, hmac_verify_time = hmac_test()  # HMAC 테스트 실행
rsa_sign_time, rsa_verify_time = rsa_test()  # RSA 테스트 실행
ecdsa_sign_time, ecdsa_verify_time = ecdsa_test()  # ECDSA 테스트 실행

# 결과 출력
print(f"HMAC Signing Time: {hmac_sign_time * ITERATIONS:.2f} ms")
print(f"HMAC Verification Time: {hmac_verify_time * ITERATIONS:.2f} ms")
print(f"RSA Signing Time: {rsa_sign_time * ITERATIONS:.2f} ms")
print(f"RSA Verification Time: {rsa_verify_time * ITERATIONS:.2f} ms")
print(f"ECDSA Signing Time: {ecdsa_sign_time * ITERATIONS:.2f} ms")
print(f"ECDSA Verification Time: {ecdsa_verify_time * ITERATIONS:.2f} ms")
