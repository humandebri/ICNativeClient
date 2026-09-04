import ICNativeClient

func makeFixtureCanister(client: ICClient) -> FixtureCanister {
    FixtureCanister(client: client)
}

func _icBindgenDecode<T: CandidConvertible>(
    _ typedValue: CandidTypedValue,
    as type: T.Type,
    context: String
) throws -> T {
    throw ICClientError.invalidCandid("consumer-owned helper")
}
