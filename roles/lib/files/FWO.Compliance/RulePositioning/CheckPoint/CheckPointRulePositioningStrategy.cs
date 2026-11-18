using FWO.Data;
using FWO.Data.DeviceSpecificSettings;
using FWO.Data.RulePositioning;
using FWO.Data.RulePositioning.CheckPoint;
using FWO.Services.RulePositioning;
using FWO.Services.RulePositioning.Blocks;
using FWO.Services.RulePositioning.CheckPoint;
using FWO.Services.RulePositioning.Diagnostics;
using CheckPointLayerGuardReadResult = FWO.Data.RulePositioning.PositioningResult<
    FWO.Data.RulePositioning.CheckPoint.CheckPointLayerGuardSnapshot,
    FWO.Services.RulePositioning.CheckPoint.CheckPointLayerGuardReadFailureCategory>;
using RulebaseGraphReadResult = FWO.Data.RulePositioning.PositioningResult<
    FWO.Services.RulePositioning.RulebaseGraphReadValue,
    FWO.Services.RulePositioning.RulebaseGraphReadFailureCategory>;
using CreationRuleNetworkResolutionResult = FWO.Data.RulePositioning.PositioningResult<
    FWO.Data.RulePositioning.CreationRuleNetworkInput,
    FWO.Compliance.RulePositioning.CreationRuleNetworkResolutionFailureCategory>;
using CreationRuleZoneResolutionResult = FWO.Data.RulePositioning.PositioningResult<
    FWO.Compliance.RulePositioning.CreationRuleZoneInput,
    FWO.Compliance.RulePositioning.CreationRuleZoneResolutionFailureCategory>;
using DesignatedZoneMatrixReadResult = FWO.Data.RulePositioning.PositioningResult<
    FWO.Compliance.RulePositioning.DesignatedZoneMatrixReadValue,
    FWO.Compliance.RulePositioning.DesignatedZoneMatrixReadFailureCategory>;
using CheckPointRecipeSelectionResult = FWO.Data.RulePositioning.PositioningResult<
    FWO.Services.RulePositioning.Blocks.PositioningRecipe<FWO.Data.RulePositioning.CheckPoint.CheckPointPositioningContext,
        FWO.Services.RulePositioning.CheckPoint.CheckPointBlockValue>,
    FWO.Compliance.RulePositioning.CheckPoint.CheckPointRecipeSelectionFailureCategory>;

namespace FWO.Compliance.RulePositioning.CheckPoint;

/// <summary>Orchestrates the ticket-aware Check Point layer-guard positioning calculation.</summary>
public sealed class CheckPointRulePositioningStrategy : IRulePositioningStrategy
{
    private readonly IRulebaseGraphSnapshotReader graphReader;
    private readonly ICreationRuleNetworkInputResolver networkResolver;
    private readonly ICheckPointLayerGuardSnapshotReader guardReader;
    private readonly IDesignatedZoneMatrixReader zoneMatrixReader;
    private readonly ICreationRuleZoneResolver zoneResolver;
    private readonly ICheckPointPositioningRecipeCatalog recipeCatalog;
    /// <summary>Executes the selected Check Point positioning recipe.</summary>
    private readonly PositioningRecipeExecutor<CheckPointPositioningContext, CheckPointBlockValue> recipeExecutor = new();

    /// <summary>Creates the Check Point positioning orchestration strategy.</summary>
    public CheckPointRulePositioningStrategy(
        IRulebaseGraphSnapshotReader graphReader,
        ICreationRuleNetworkInputResolver networkResolver,
        ICheckPointLayerGuardSnapshotReader guardReader,
        IDesignatedZoneMatrixReader zoneMatrixReader,
        ICreationRuleZoneResolver zoneResolver,
        ICheckPointPositioningRecipeCatalog recipeCatalog)
    {
        this.graphReader = graphReader ?? throw new ArgumentNullException(nameof(graphReader));
        this.networkResolver = networkResolver ?? throw new ArgumentNullException(nameof(networkResolver));
        this.guardReader = guardReader ?? throw new ArgumentNullException(nameof(guardReader));
        this.zoneMatrixReader = zoneMatrixReader ?? throw new ArgumentNullException(nameof(zoneMatrixReader));
        this.zoneResolver = zoneResolver ?? throw new ArgumentNullException(nameof(zoneResolver));
        this.recipeCatalog = recipeCatalog ?? throw new ArgumentNullException(nameof(recipeCatalog));
    }

    /// <inheritdoc />
    public bool CanHandle(DeviceType deviceType, ProvisioningPositioningAlgorithm positioningAlgorithm)
    {
        return deviceType != null
            && deviceType.Id == DeviceTypeIds.kCheckPointR8x
            && IsUsableAlgorithm(positioningAlgorithm)
            && recipeCatalog.SupportsAlgorithm(positioningAlgorithm);
    }

    /// <inheritdoc />
    public async Task<RulePositioningResult> CalculateAsync(
        RulePositioningContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            object? entry = context == null ? null : new
            {
                context.ImplementationTask,
                parentRequestTask = RulePositioningForensicProjection.RequestTask(context.ParentRequestTask),
                targetGateway = RulePositioningForensicProjection.Device(context.TargetGateway),
                targetManagement = RulePositioningForensicProjection.Management(context.TargetManagement),
                context.EffectiveSettings,
                ticketRequestTasks = RulePositioningForensicProjection.RequestTasks(context.TicketRequestTasks),
                context.Configuration
            };
            RulePositioningForensicCapture.Record("strategy", "strategy-entry", entry);
            return await CalculateCoreAsync(context!, cancellationToken);
        }
        catch (OperationCanceledException exception)
            when (cancellationToken.IsCancellationRequested
                || cancellationToken.CanBeCanceled && exception.CancellationToken == cancellationToken)
        {
            throw;
        }
        catch (Exception exception)
        {
            RulePositioningForensicCapture.Record("strategy", "strategy-exception", new
            {
                exceptionType = exception.GetType().FullName
            });
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
    }

    /// <summary>Runs the validated customer orchestration without exception translation.</summary>
    private async Task<RulePositioningResult> CalculateCoreAsync(
        RulePositioningContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RulePositioningFailureCategory? validationFailure =
            RulePositioningContextValidator.ValidateTicketAwareContext(context);
        if (validationFailure.HasValue)
        {
            return Failure(validationFailure.Value);
        }

        ProvisioningPositioningAlgorithm algorithm = context.EffectiveSettings.PositioningAlgorithm;
        if (!CanHandle(context.TargetGateway.DeviceType, algorithm))
        {
            return Failure(RulePositioningFailureCategory.PositioningMethodNotImplemented);
        }

        PositioningResult<CheckPointSectionNameTemplate, CheckPointSectionNameTemplateFailureCategory> templateResult =
            CheckPointSectionNameTemplate.Parse(context.EffectiveSettings.CheckPointLayerGuardSectionNameTemplate);
        RulePositioningForensicCapture.Record("strategy", "template-result", new
        {
            template = context.EffectiveSettings.CheckPointLayerGuardSectionNameTemplate,
            result = templateResult
        });
        if (!templateResult.TryGetValue(out CheckPointSectionNameTemplate? sectionNameTemplate))
        {
            templateResult.TryGetFailure(out CheckPointSectionNameTemplateFailureCategory templateFailure);
            return KnownFailure(
                "section-name template",
                RulePositioningFailureCategory.ConfigurationInvalid,
                templateFailure,
                "The Check Point layer-guard section-name template is invalid.");
        }

        InputPreparationResult preparation = await PrepareInputsAsync(
            context,
            sectionNameTemplate.RequiredVariables.Count > 0,
            cancellationToken);
        if (preparation.PreparationFailure != null)
        {
            return preparation.PreparationFailure;
        }
        PreparedInputs inputs = preparation.Inputs!;
        RulePositioningForensicCapture.Record("strategy", "prepared-inputs", inputs);

        PositioningResult<string, CheckPointLayerGuardSectionNameFailureCategory> sectionNameResult =
            CheckPointLayerGuardSectionNameResolver.Resolve(sectionNameTemplate, inputs.ZoneInput);
        RulePositioningForensicCapture.Record("strategy", "section-name", new
        {
            template = sectionNameTemplate,
            inputs.ZoneInput,
            result = sectionNameResult
        });
        if (!sectionNameResult.TryGetValue(out string? normalizedSectionName))
        {
            sectionNameResult.TryGetFailure(out CheckPointLayerGuardSectionNameFailureCategory sectionNameFailure);
            return KnownFailure(
                "section-name resolution",
                RulePositioningFailureCategory.ConfigurationInvalid,
                sectionNameFailure,
                "The Check Point layer-guard section name could not be resolved.");
        }

        CheckPointLayerGuardZonePairPositioningInput positioningInput = new(
            inputs.NetworkInput,
            inputs.GuardSnapshot);
        CheckPointRecipeSelectionResult selectionResult = recipeCatalog.SelectRecipe(
            algorithm,
            positioningInput,
            normalizedSectionName);
        RulePositioningForensicCapture.Record("strategy", "recipe-selection", new
        {
            algorithm,
            normalizedSectionName,
            positioningInput,
            result = selectionResult
        });
        if (!selectionResult.TryGetValue(out PositioningRecipe<CheckPointPositioningContext, CheckPointBlockValue>? recipe))
        {
            return MapSelectionFailure(selectionResult);
        }

        cancellationToken.ThrowIfCancellationRequested();
        CheckPointPositioningContext checkPointContext = new(
            context,
            inputs.Snapshot,
            positioningInput);
        PositioningBlockResult<CheckPointBlockValue> executionResult = await recipeExecutor.ExecuteAsync(
            recipe,
            checkPointContext,
            cancellationToken);
        RulePositioningForensicCapture.Record("strategy", "recipe-result", new
        {
            algorithm,
            normalizedSectionName,
            executionResult
        });
        if (executionResult is not PositioningBlockSuccess<CheckPointBlockValue> executionSuccess)
        {
            return MapExecutionFailure(executionResult);
        }
        if (executionSuccess.Value is not CheckPointPositionValue positionValue
            || positionValue.Position.PositioningAlgorithm != algorithm)
        {
            return KnownFailure(
                "recipe execution result",
                RulePositioningFailureCategory.CalculationFailed,
                StrategyFailureCategory.UnexpectedPositionResult,
                "The positioning recipe returned an unexpected result.");
        }

        return new RulePositioningSuccess(positionValue.Position);
    }

    /// <summary>Loads and validates the graph, effective networks, guards, matrix, and zones.</summary>
    private async Task<InputPreparationResult> PrepareInputsAsync(
        RulePositioningContext context,
        bool requiresZones,
        CancellationToken cancellationToken)
    {
        RulebaseGraphReadResult graphResult = await graphReader.ReadAsync(
            context.TargetManagement.Id,
            context.TargetGateway.Id,
            cancellationToken);
        if (!graphResult.TryGetValue(out RulebaseGraphReadValue? graphValue))
        {
            return InputPreparationResult.Failed(MapGraphFailure(graphResult));
        }

        cancellationToken.ThrowIfCancellationRequested();
        CreationRuleNetworkResolutionResult networkResult = await networkResolver.ResolveAsync(
            context.ParentRequestTask,
            context.TicketRequestTasks!,
            cancellationToken);
        if (!networkResult.TryGetValue(out CreationRuleNetworkInput? networkInput))
        {
            return InputPreparationResult.Failed(MapNetworkFailure(networkResult));
        }

        cancellationToken.ThrowIfCancellationRequested();
        CheckPointLayerGuardReadResult guardResult = await guardReader.ReadAsync(
            graphValue.Snapshot,
            graphValue.ImportId,
            cancellationToken);
        if (!guardResult.TryGetValue(out CheckPointLayerGuardSnapshot? guardSnapshot))
        {
            return InputPreparationResult.Failed(MapGuardFailure(guardResult));
        }

        CreationRuleZoneInput? zoneInput = null;
        if (requiresZones)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RulePositioningConfiguration configuration = context.Configuration!;
            DesignatedZoneMatrixReadResult matrixResult = await zoneMatrixReader.ReadAsync(
                configuration.DesignatedZoneMatrixId,
                cancellationToken);
            if (!matrixResult.TryGetValue(out DesignatedZoneMatrixReadValue? matrixValue))
            {
                return InputPreparationResult.Failed(MapMatrixFailure(matrixResult));
            }

            cancellationToken.ThrowIfCancellationRequested();
            CreationRuleZoneResolutionResult zoneResult = await zoneResolver.ResolveAsync(
                networkInput,
                matrixValue.NetworkZones,
                configuration,
                cancellationToken);
            if (!zoneResult.TryGetValue(out zoneInput))
            {
                return InputPreparationResult.Failed(MapZoneFailure(zoneResult));
            }
        }

        return InputPreparationResult.Succeeded(new PreparedInputs(
            graphValue.Snapshot,
            networkInput,
            guardSnapshot,
            zoneInput));
    }

    /// <summary>Validated data required to select and execute one positioning recipe.</summary>
    private sealed record PreparedInputs(
        RulebaseGraphSnapshot Snapshot,
        CreationRuleNetworkInput NetworkInput,
        CheckPointLayerGuardSnapshot GuardSnapshot,
        CreationRuleZoneInput? ZoneInput);

    /// <summary>Result of preparing positioning inputs without throwing domain failures.</summary>
    private sealed record InputPreparationResult(PreparedInputs? Inputs, RulePositioningFailure? PreparationFailure)
    {
        /// <summary>Creates a successful preparation result.</summary>
        internal static InputPreparationResult Succeeded(PreparedInputs inputs) => new(inputs, null);

        /// <summary>Creates a failed preparation result.</summary>
        internal static InputPreparationResult Failed(RulePositioningFailure failure) => new(null, failure);
    }

    /// <summary>Maps effective-network failures to the public positioning contract.</summary>
    private static RulePositioningFailure MapNetworkFailure(CreationRuleNetworkResolutionResult result)
    {
        if (!result.TryGetFailure(out CreationRuleNetworkResolutionFailureCategory failureCategory))
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failureCategory switch
        {
            CreationRuleNetworkResolutionFailureCategory.UnsupportedTask =>
                RulePositioningFailureCategory.UnsupportedTask,
            CreationRuleNetworkResolutionFailureCategory.GroupQueryFailed or
                CreationRuleNetworkResolutionFailureCategory.UnexpectedFailure =>
                RulePositioningFailureCategory.CalculationFailed,
            _ => RulePositioningFailureCategory.InvalidInput
        };
        return KnownFailure(
            "creation-rule networks",
            category,
            failureCategory,
            failureCategory.GetDiagnostic());
    }

    /// <summary>Maps fixed-import layer-guard failures to the public positioning contract.</summary>
    private static RulePositioningFailure MapGuardFailure(CheckPointLayerGuardReadResult result)
    {
        if (!result.TryGetFailure(out CheckPointLayerGuardReadFailureCategory failureCategory))
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failureCategory is CheckPointLayerGuardReadFailureCategory.InvalidInput
                or CheckPointLayerGuardReadFailureCategory.ScopeMismatch
                ? RulePositioningFailureCategory.InvalidInput
                : RulePositioningFailureCategory.CalculationFailed;
        return KnownFailure("layer guards", category, failureCategory, failureCategory.GetDiagnostic());
    }

    /// <summary>Checks whether an algorithm is defined and non-default.</summary>
    private static bool IsUsableAlgorithm(ProvisioningPositioningAlgorithm algorithm)
    {
        return algorithm != ProvisioningPositioningAlgorithm.Undefined && Enum.IsDefined(algorithm);
    }

    /// <summary>Maps graph-reader failures to the Phase 1 contract.</summary>
    private static RulePositioningFailure MapGraphFailure(RulebaseGraphReadResult result)
    {
        if (!result.TryGetFailure(out RulebaseGraphReadFailureCategory failureCategory))
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failureCategory is
            RulebaseGraphReadFailureCategory.InvalidInput or RulebaseGraphReadFailureCategory.ScopeMismatch
                ? RulePositioningFailureCategory.InvalidInput
                : RulePositioningFailureCategory.CalculationFailed;
        return KnownFailure("rulebase graph", category, failureCategory, failureCategory.GetDiagnostic());
    }

    /// <summary>Maps designated-matrix-reader failures to the Phase 1 contract.</summary>
    private static RulePositioningFailure MapMatrixFailure(DesignatedZoneMatrixReadResult result)
    {
        if (!result.TryGetFailure(out DesignatedZoneMatrixReadFailureCategory failureCategory))
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failureCategory is
            DesignatedZoneMatrixReadFailureCategory.ConfigurationInvalid
                or DesignatedZoneMatrixReadFailureCategory.MatrixUnavailable
                ? RulePositioningFailureCategory.ConfigurationInvalid
                : RulePositioningFailureCategory.CalculationFailed;
        return KnownFailure("designated zone matrix", category, failureCategory, failureCategory.GetDiagnostic());
    }

    /// <summary>Maps zone-resolution failures to the Phase 1 contract.</summary>
    private static RulePositioningFailure MapZoneFailure(CreationRuleZoneResolutionResult result)
    {
        if (!result.TryGetFailure(out CreationRuleZoneResolutionFailureCategory failureCategory))
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failureCategory switch
        {
            CreationRuleZoneResolutionFailureCategory.InvalidInput
                or CreationRuleZoneResolutionFailureCategory.UnsupportedObject
                or CreationRuleZoneResolutionFailureCategory.InvalidAddress => RulePositioningFailureCategory.InvalidInput,
            CreationRuleZoneResolutionFailureCategory.UnsupportedTask => RulePositioningFailureCategory.UnsupportedTask,
            CreationRuleZoneResolutionFailureCategory.InvalidZoneData => RulePositioningFailureCategory.ConfigurationInvalid,
            _ => RulePositioningFailureCategory.CalculationFailed
        };
        return KnownFailure(
            "creation-rule zones",
            category,
            failureCategory,
            failureCategory.GetDiagnostic());
    }

    /// <summary>Maps recipe-selection failures to the Phase 1 contract.</summary>
    private static RulePositioningFailure MapSelectionFailure(CheckPointRecipeSelectionResult result)
    {
        if (!result.TryGetFailure(out CheckPointRecipeSelectionFailureCategory failureCategory))
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failureCategory == CheckPointRecipeSelectionFailureCategory.NoMatchingRecipe
            ? RulePositioningFailureCategory.PositioningMethodNotImplemented
            : RulePositioningFailureCategory.ConfigurationInvalid;
        return KnownFailure("recipe selection", category, failureCategory, failureCategory.GetDiagnostic());
    }

    /// <summary>Maps recipe-execution failures to the Phase 1 contract.</summary>
    private static RulePositioningFailure MapExecutionFailure(PositioningBlockResult<CheckPointBlockValue> result)
    {
        if (result is not PositioningBlockFailure<CheckPointBlockValue> failure)
        {
            return Failure(RulePositioningFailureCategory.CalculationFailed);
        }
        RulePositioningFailureCategory category = failure.Category == PositioningBlockFailureCategory.InvalidRecipe
                ? RulePositioningFailureCategory.ConfigurationInvalid
                : RulePositioningFailureCategory.CalculationFailed;
        return KnownFailure(
            "recipe execution",
            category,
            failure.Category,
            failure.Diagnostic,
            failure.OriginatingBlockKind);
    }

    /// <summary>Creates a Phase 1 failure with its fixed safe diagnostic.</summary>
    private static RulePositioningFailure Failure(RulePositioningFailureCategory category)
    {
        return new RulePositioningFailure(category);
    }

    /// <summary>Creates a failure from one typed lower-level cause.</summary>
    private static RulePositioningFailure KnownFailure(
        string stage,
        RulePositioningFailureCategory category,
        Enum specificCategory,
        string diagnostic,
        string? originatingBlockKind = null)
    {
        string block = originatingBlockKind == null ? "" : $" / {originatingBlockKind}";
        return new RulePositioningFailure(
            category,
            $"{stage}{block} / {specificCategory}: {diagnostic}");
    }

    private enum StrategyFailureCategory
    {
        UnexpectedPositionResult
    }
}
