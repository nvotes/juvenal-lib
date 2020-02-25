module.exports = {
    globals: {
        "ts-jest": {
            tsConfig: "tsconfig.json"
        }
    },
    moduleFileExtensions: [
        "ts",
        "js"
    ],
    transform: {
        "^.+\\.ts$": "ts-jest"
    },
    testMatch: [
        // "**/*.test.ts"
        "**/helios.test.ts"
    ],
    verbose: true,
    testEnvironment: "node"
};
