namespace FWO.Api.Client
{
    /// <summary>Identifies where a non-throwing API error originated.</summary>
    public enum ApiResponseErrorOrigin
    {
        None,
        Unknown,
        GraphQlResponse,
        ClientException
    }

    /// <summary>
    /// Wraps API data with optional error information to avoid exceptions in callers.
    /// </summary>
    public sealed class ApiResponse<ResponseType>
    {
        /// <summary>
        /// The successfully deserialized result, if available.
        /// </summary>
        public ResponseType? Result { get; }
        /// <summary>
        /// Errors returned by the API, if any.
        /// </summary>
        public string[]? Errors { get; }
        /// <summary>Identifies whether errors came from GraphQL or from the local client path.</summary>
        public ApiResponseErrorOrigin ErrorOrigin { get; }
        /// <summary>
        /// Indicates whether the response contains errors.
        /// </summary>
        public bool HasErrors => Errors is { Length: > 0 };

        /// <summary>
        /// Creates a successful response wrapper.
        /// </summary>
        public ApiResponse(ResponseType result)
        {
            Result = result;
            ErrorOrigin = ApiResponseErrorOrigin.None;
        }

        /// <summary>
        /// Creates a response wrapper containing error messages.
        /// </summary>
        public ApiResponse(params string[] errors)
            : this(ApiResponseErrorOrigin.Unknown, errors)
        { }

        /// <summary>Creates a response wrapper containing errors of a known origin.</summary>
        public ApiResponse(ApiResponseErrorOrigin errorOrigin, params string[] errors)
        {
            Errors = errors;
            ErrorOrigin = errorOrigin;
        }
    }
}
