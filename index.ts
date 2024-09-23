import { generateKeyPairSync, publicEncrypt, privateDecrypt } from 'crypto';
import { readFile, writeFile } from 'fs/promises';

// Générer une paire de clés RSA de 4096 bits pour sécuriser la transmission du tableau
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Génération du tableau de substitution (chaque lettre est mappée à un nombre aléatoire)
function generateSubstitutionTable(): Record<string, number> {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const usedNumbers = new Set<number>();
    const table: Record<string, number> = {};

    for (const letter of alphabet) {
        let randomNumber: number;
        do {
            randomNumber = Math.floor(Math.random() * 100) + 1; // Générer un nombre entre 1 et 100
        } while (usedNumbers.has(randomNumber));
        usedNumbers.add(randomNumber);
        table[letter] = randomNumber;
    }

    return table;
}

// Fonction de chiffrement utilisant le tableau de substitution
function encryptMessage(message: string, table: Record<string, number>): string {
    return message
        .toUpperCase()
        .split('')
        .map(char => {
            if (table[char]) {
                return table[char].toString();
            } else {
                return char; // Conserver les caractères non alphabétiques
            }
        })
        .join('$'); // Séparer les nombres par des tirets
}

// Fonction de déchiffrement utilisant le tableau de substitution
function decryptMessage(encryptedMessage: string, table: Record<string, number>): string {
    const reverseTable = Object.fromEntries(
        Object.entries(table).map(([char, num]) => [num, char])
    );

    return encryptedMessage
        .split('$')
        .map(num => {
            return reverseTable[parseInt(num)] || num;
        })
        .join('');
}

// Fonction pour chiffrer le tableau de substitution avec RSA (clé publique)
function encryptTable(table: Record<string, number>, publicKey: string): string {
    const tableString = JSON.stringify(table);
    const buffer = Buffer.from(tableString, 'utf8');
    const encryptedTable = publicEncrypt(publicKey, buffer);
    return encryptedTable.toString('base64');
}

// Fonction pour déchiffrer le tableau de substitution avec RSA (clé privée)
function decryptTable(encryptedTable: string, privateKey: string): Record<string, number> {
    const buffer = Buffer.from(encryptedTable, 'base64');
    const decryptedTable = privateDecrypt(privateKey, buffer);
    return JSON.parse(decryptedTable.toString('utf8'));
}

// Fonction pour lire un fichier et renvoyer son contenu sous forme de chaîne de caractères
async function readMessageFromFile(filePath: string): Promise<string> {
    try {
        const data = await readFile(filePath, 'utf8');
        return data;
    } catch (error: unknown) {
        if (error instanceof Error) {
            throw new Error(`Erreur lors de la lecture du fichier: ${error.message}`);
        } else {
            throw new Error("Erreur inconnue lors de la lecture du fichier.");
        }
    }
}

// Fonction pour écrire un message chiffré dans un fichier
async function writeMessageToFile(filePath: string, message: string): Promise<void> {
    try {
        await writeFile(filePath, message, 'utf8');
        console.log(`Message écrit avec succès dans le fichier: ${filePath}`);
    } catch (error: unknown) {
        if (error instanceof Error) {
            throw new Error(`Erreur lors de l'écriture dans le fichier: ${error.message}`);
        } else {
            throw new Error("Erreur inconnue lors de l'écriture dans le fichier.");
        }
    }
}

// Exemple d'exécution
(async () => {
    const inputFilePath = './shadow/message.txt'; // Chemin vers le fichier d'entrée contenant le message à chiffrer
    const encryptedFilePath = './shadow/encrypted_message.txt'; // Chemin vers le fichier de sortie pour le message chiffré
    const decryptedFilePath = './shadow/decrypted_message.txt'; // Chemin vers le fichier de sortie pour le message déchiffré

    try {
        // Lire le message à partir du fichier texte
        const message = await readMessageFromFile(inputFilePath);
        console.log("Message original lu depuis le fichier:", message);

        // Générer un tableau de substitution
        const substitutionTable = generateSubstitutionTable();
        console.log("Table de substitution générée:", substitutionTable);

        // Chiffrer le tableau de substitution avec RSA
        const encryptedTable = encryptTable(substitutionTable, publicKey);
        console.log("Table de substitution chiffrée:", encryptedTable);

        // Déchiffrer le tableau de substitution avec RSA
        const decryptedTable = decryptTable(encryptedTable, privateKey);
        console.log("Table de substitution déchiffrée:", decryptedTable);

        // Chiffrement du message avec la table de substitution déchiffrée
        const encryptedMessage = encryptMessage(message, decryptedTable);
        console.log("Message chiffré:", encryptedMessage);

        // Écrire le message chiffré dans un fichier
        await writeMessageToFile(encryptedFilePath, encryptedMessage);

        // Déchiffrement du message
        const decryptedMessage = decryptMessage(encryptedMessage, decryptedTable);
        console.log("Message déchiffré:", decryptedMessage);

        // Écrire le message déchiffré dans un fichier
        await writeMessageToFile(decryptedFilePath, decryptedMessage);

    } catch (error: unknown) {
        if (error instanceof Error) {
            console.error("Erreur:", error.message);
        } else {
            console.error("Erreur inconnue:", error);
        }
    }
})();