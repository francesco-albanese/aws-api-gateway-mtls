# Lambda rules

- When creating a Lambda, if the lambda needs to call other functions with a specific functionality, extract those functions outside the `handler.py` giving it a meaningful name.
- Example: extract metadata certs from Dynamodb, create `extract_certs.py` and import the needed function into `handler.py` for consumption.
- Make sure to follow single responsibility principle, keep the code modular
