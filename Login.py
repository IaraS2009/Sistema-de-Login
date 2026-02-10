import hashlib
import re
import os
import hmac
import getpass

utilizadores = {}

def validar_dados(username, password, email=""):
    if not username or not password:
        return False, "Campos vazios não são permitidos!"
    if len(password) < 6:
        return False, "A palavra-passe deve ter pelo menos 6 caracteres!"
    if email:
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            return False, "Formato de email inválido!"
    return True, "Dados válidos!"

def gerar_salt():
    return os.urandom(16)

def hash_password(password, salt):
    return hashlib.sha256(salt + password.encode()).hexdigest()

def registar_utilizador(username, password, email=""):
    valido, mensagem = validar_dados(username, password, email)
    if not valido:
        print(mensagem)
        return False
    if username in utilizadores:
        print("Utilizador já existe!")
        return False
    salt = gerar_salt()
    password_hash = hash_password(password, salt)
    utilizadores[username] = (salt, password_hash)
    print("Registo efetuado com sucesso!")
    return True

def fazer_login(username, password):
    valido, mensagem = validar_dados(username, password)
    if not valido:
        print(mensagem)
        return False
    if username not in utilizadores:
        print("Utilizador ou palavra-passe incorretos!")
        return False
    salt, stored_hash = utilizadores[username]
    input_hash = hash_password(password, salt)
    if hmac.compare_digest(input_hash, stored_hash):
        print("Login efetuado com sucesso!")
        return True
    else:
        print("Utilizador ou palavra-passe incorretos!")
        return False

def main():
    while True:
        print("\n--- Sistema de Login ---")
        print("1. Registar novo utilizador")
        print("2. Fazer login")
        print("3. Sair")
        opcao = input("Escolha uma opção: ")
        if opcao == "1":
            username = input("Nome de utilizador: ")
            password = input("Palavra-passe: ")
            email = input("Email (opcional): ")
            registar_utilizador(username, password, email)
        elif opcao == "2":
            username = input("Nome de utilizador: ")
            password = getpass.getpass("Palavra-passe: ")
            fazer_login(username, password)
        elif opcao == "3":
            print("Adeus!")
            break
        else:
            print("Opção inválida!")

if __name__ == "__main__":
    main()