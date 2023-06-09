from qiskit_ibm_provider import IBMProvider
from qiskit import QuantumCircuit, ClassicalRegister, QuantumRegister, transpile, assemble, Aer, execute
from qiskit.visualization import plot_histogram
import math
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
start_time = time.time()
provider = IBMProvider()
# get IBM's simulator backend
simulator_backend = provider.get_backend('ibmq_qasm_simulator')
#IBMProvider.save_account(token='your_IBM_API_token')
def TRNG(n):
    
    #Set the number of quantum registers and classical registers
    num_qubits = 1024
    quantum_registers = QuantumRegister(num_qubits)
    classical_registers = ClassicalRegister(num_qubits)#num_qubits = num_classical_bits

    #Apply Hadamard gate to all qubits
    circuit = QuantumCircuit(quantum_registers, classical_registers)

    circuit.h(quantum_registers)  # Apply Hadamard gate to all qubits

    #Apply measurement to all qubits
    circuit.measure(quantum_registers, classical_registers)

    shots = 1

    # Simulate the circuit
    simulator = Aer.get_backend('aer_simulator')
    job = execute(circuit, simulator, shots=shots)
    result = job.result()

    #Get the counts of the measurement outcomes
    counts = result.get_counts(circuit)
    result = counts.popitem()[0]
    result = int(result, 2)
    # Convert binary numbers to decimal
    result = result.to_bytes((result.bit_length() + 7) // 8, 'big')
    #print (result)
    return result
#Generating RSA keys
key = RSA.generate(1024, TRNG)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Saving keys to files
with open("private_key.pem", "wb") as file:
    file.write(private_key)
with open("public_key.pem", "wb") as file:
    file.write(public_key)

# Reading content of file tosign.txt
with open("tosign.txt", "r") as file:
    data = file.read()

# Hashing content of file
hash = SHA1.new(data.encode())

# Reading private and public key from files
with open("private_key.pem", "rb") as file:
    private_key_read = file.read()
with open("public_key.pem", "rb") as file:
    public_key_read = file.read()

# Signing hash
private_key = RSA.import_key(private_key_read)
signer = pkcs1_15.new(private_key)
signature = signer.sign(hash)

# Write signature to file tosign.txt.sig
with open("tosign.txt.sig", "wb") as file:
    file.write(signature)

# Verification of signature
def Verrify():

    # Reading content of file tosign.txt
    with open("tosign.txt.sig", "rb") as file:
        signature = file.read()
    # Reading private and public key from files
    with open("private_key.pem", "rb") as file:
        private_key_read = file.read()
    with open("public_key.pem", "rb") as file:
        public_key_read = file.read()
        # Reading content of file tosign.txt
    with open("tosign.txt", "r") as file:
        data = file.read()

    # Hashing content of file
    hash = SHA1.new(data.encode())
    public_key = RSA.import_key(public_key_read)
    verifier = pkcs1_15.new(public_key)
    print(hash)
    print(signature)
    # Try to verify signature
    try:
        verifier.verify(hash, signature)
        print("Podpis jest poprawny.")
    except (ValueError, TypeError):
        print("Podpis jest niepoprawny.")
    
print("--- %s seconds ---" % (time.time() - start_time))


while(True):
    val = input("What do you want to do: \n 1.Check if file has changed \n 2.Change .txt file \n 3.Change .sig file \n 4.End \n")
    if val == "1" :
        Verrify()
    elif val == "2" :
        with open("tosign.txt", 'a') as file:
            file.write("this line was added additionally")
            file.write('\n')
        Verrify()
    elif val == "3" :
        with open("tosign.txt.sig", 'wb') as file:
            file.write(b'this line was added additionally')
        Verrify()
    elif val == "4" :
        break
    else :
        print('wrong input')
