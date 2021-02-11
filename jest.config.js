module.exports = {
    globals: {
        "ts-jest": {
            tsconfig: "tsconfig.json"
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
        "**/*.test.ts"
    ],
    verbose: true,
    testEnvironment: "node"
};
