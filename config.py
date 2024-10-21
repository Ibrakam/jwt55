from dotenv import dotenv_values

settings = dotenv_values(".env")

algorithm = settings["ALGORITHM"]
secret_key = settings["SECRET_KEY"]
access_token_exp_minutes = int(settings["ACCESS_TOKEN_EXPIRE_MINUTES"])
