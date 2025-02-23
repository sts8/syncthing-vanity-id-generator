import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from parallel_execution import benchmark_iterations_per_second, run_parallel
from syncthing_id_generator import create_key_and_cert, calculate_syncthing_id


def write_key_and_cert_to_disk(output_path, key, cert):
    output_path.mkdir()
    key_file = output_path.joinpath("key.pem")
    cert_file = output_path.joinpath("cert.pem")

    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def run():
    regex = r"^AAA"
    key, cert = create_key_and_cert()
    syncthing_id = calculate_syncthing_id(cert)

    if bool(re.match(regex, syncthing_id)):
        output_path = Path(syncthing_id)
        write_key_and_cert_to_disk(output_path, key, cert)
        print(f"FOUND: {syncthing_id}")


def main():
    batch_size = benchmark_iterations_per_second(run)
    run_parallel(run, batch_size)


if __name__ == '__main__':
    main()
