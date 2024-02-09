import secrets

p = pow(2, 255) - 19

base = 15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960

def findPositiveModulus(a, p):
	""""Calculates the positive modulus of a number using the given parameters."
	Parameters:
	- a (int): The number to be calculated.
	- p (int): The modulus value.
	Returns:
	- int: The positive modulus of the given number.
	Processing Logic:
	- If the given number is negative, add the modulus value multiplied by the absolute value of the number divided by the modulus value, and then add the modulus value again. Finally, calculate the modulus of the result using the given modulus value.
	- Example: findPositiveModulus(-5, 3) returns 1."""
	
	if a < 0:
		a = (a + p * int(abs(a)/p) + p) % p
	return a

def textToInt(text):
	""""Converts text to an integer using UTF-8 encoding."
	Parameters:
	- text (str): Text to be converted to integer.
	Returns:
	- int: Integer representation of the input text.
	Processing Logic:
	- Encode text using UTF-8.
	- Convert encoded text to hexadecimal.
	- Convert hexadecimal to integer.
	- Return the integer value.
	Example:
	>>> textToInt("Hello")
	72623859790382856"""
	
	encoded_text = text.encode('utf-8')
	hex_text = encoded_text.hex()
	int_text = int(hex_text, 16)
	return int_text
	
def gcd(a, b):
    """Calculates the greatest common divisor of two numbers.
    Parameters:
        - a (int): First number.
        - b (int): Second number.
    Returns:
        - int: Greatest common divisor of a and b.
    Processing Logic:
        - Loop until a is 0.
        - Calculate remainder of b divided by a.
        - Assign a to b and remainder to a.
        - Return b as the greatest common divisor.
    Example:
        gcd(12, 18) # returns 6"""
    
    while a != 0:
        a, b = b % a, a
    return b

def findModInverse(a, m): #modular inverse of a mod m
	"""Function to find the modular inverse of a mod m.
	Parameters:
	- a (int): The number whose inverse is to be found.
	- m (int): The modulus.
	Returns:
	- int: The modular inverse of a mod m.
	Processing Logic:
	- Handles negative values of a by converting them to positive values.
	- Checks if a and m are relatively prime, if not, returns None.
	- Uses the Extended Euclidean Algorithm to calculate the inverse.
	- Returns the inverse modulo m."""
	
	
	if a < 0:
		a = (a + m * int(abs(a)/m) + m) % m
	
	if gcd(a, m) != 1:
		return None # no mod inverse if a & m aren't relatively prime
	
	# Calculate using the Extended Euclidean Algorithm:
	u1, u2, u3 = 1, 0, a
	v1, v2, v3 = 0, 1, m
	while v3 != 0:
		q = u3 // v3 # // is the integer division operator
		v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
	return u1 % m

def applyDoubleAndAddMethod(P, k, a, d, mod):
	"""Apply Double and Add Method for Elliptic Curve Cryptography
	Parameters:
	- P (tuple): Base point on the elliptic curve.
	- k (int): Scalar value used for point multiplication.
	- a (int): Coefficient a of the elliptic curve equation.
	- d (int): Coefficient d of the elliptic curve equation.
	- mod (int): Modulus used for arithmetic operations.
	Returns:
	- tuple: Resulting point after applying the double and add method.
	Processing Logic:
	- Convert k to binary representation.
	- Loop through each bit of k.
	- Double the addition point for each bit.
	- If the bit is 1, add the base point to the addition point.
	- Return the final addition point.
	Example:
	applyDoubleAndAddMethod((3, 5), 13, 2, 3, 17)
	# Returns (8, 10)"""
	
	
	additionPoint = (P[0], P[1])
	
	kAsBinary = bin(k) #0b1111111001
	kAsBinary = kAsBinary[2:len(kAsBinary)] #1111111001
	#print(kAsBinary)
	
	for i in range(1, len(kAsBinary)):
		currentBit = kAsBinary[i: i+1]
		#always apply doubling
		additionPoint = pointAddition(additionPoint, additionPoint, a, d, mod)
		
		if currentBit == '1':
			#add base point
			additionPoint = pointAddition(additionPoint, P, a, d, mod)
	
	return additionPoint

def pointAddition(P, Q, a, d, mod):
	"""Function to perform point addition on two points in an elliptic curve.
	Parameters:
	- P (tuple): Coordinates of the first point.
	- Q (tuple): Coordinates of the second point.
	- a (int): Parameter of the elliptic curve.
	- d (int): Parameter of the elliptic curve.
	- mod (int): Modulus used in the calculation.
	Returns:
	- tuple: Coordinates of the resulting point after point addition.
	Processing Logic:
	- Calculate x and y coordinates separately.
	- Use findModInverse function to find the inverse of a value.
	- Use modulus to ensure values stay within the curve.
	- Return the resulting coordinates as a tuple.
	Example:
	>>> pointAddition((2,3), (5,7), 1, 2, 11)
	(9, 6)"""
	
	x1 = P[0]; y1 = P[1]
	x2 = Q[0]; y2 = Q[1]
	
	x3 = (((x1*y2 + y1*x2) % mod) * findModInverse(1+d*x1*x2*y1*y2, mod)) % mod
	y3 = (((y1*y2 - a*x1*x2) % mod) * findModInverse(1- d*x1*x2*y1*y2, mod)) % mod
	
	return x3, y3
	
#ax^2 + y^2  = 1 + dx^2y^2
a = -1; d = findPositiveModulus(-121665 * findModInverse(121666, p), p) #ed25519
#print("curve: ",a,"x^2 + y^2 = 1 + ",d,"x^2 y^2")
x0 = base[0]; y0 = base[1]

print("----------------------")
print("Key Generation: ")
privateKey = secrets.SystemRandom().getrandbits(256) #32 byte secret key
#print("private key: ",privateKey)

publicKey = applyDoubleAndAddMethod(base, privateKey, a, d, p)
print("public key: ", publicKey)

message = textToInt("Hello, world!")

def hashing(message):
	"""Hashes a given message using SHA512 algorithm and returns the hashed value.
	Parameters:
	- message (str): The message to be hashed.
	Returns:
	- int: The hashed value of the message.
	Processing Logic:
	- Import hashlib library.
	- Encode the message using UTF-8.
	- Hash the encoded message using SHA512 algorithm.
	- Convert the hashed value from hexadecimal to integer.
	- Return the hashed value."""
	
	import hashlib
	return int(hashlib.sha512(str(message).encode("utf-8")).hexdigest(), 16)

#---------------------------------------
#sign
r = hashing(hashing(message) + message) % p
R = applyDoubleAndAddMethod(base, r, a, d, p)

h = hashing(R[0] + publicKey[0] + message) % p

s = (r + h * privateKey) #% p

print("----------------------")
print("Signing:")
print("message: ",message)
print("Signature (R, s)")
print("R: ",R)
print("s: ",s)


#-----------------------------------
#verify
h = hashing(R[0] + publicKey[0] + message) % p

P1 = applyDoubleAndAddMethod(base, s, a, d, p)

P2 = pointAddition(R, applyDoubleAndAddMethod(publicKey, h, a, d, p), a, d, p)

print("----------------------")
print("Verification:")
print("P1: ",P1)
print("P2: ",P2)

if P1[0] == P2[0] and P1[1] == P2[1]:
	print("signature is valid")
else:
	print("signature violation detected!")

#----------------------------------
