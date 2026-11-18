using FWO.Services.RulePositioning.Diagnostics;

namespace FWO.Services.RulePositioning.Blocks;

/// <summary>
/// Evaluates validated positioning recipes depth-first and stops at the first failure.
/// </summary>
public sealed class PositioningRecipeExecutor<TContext, TOutput>
{
    /// <summary>
    /// Evaluates one recipe without retaining evaluation state between calls.
    /// </summary>
    public Task<PositioningBlockResult<TOutput>> ExecuteAsync(
        PositioningRecipe<TContext, TOutput>? recipe,
        TContext context,
        CancellationToken cancellationToken = default)
    {
        if (recipe == null)
        {
            RulePositioningForensicCapture.Record("recipe-execution", "recipe-rejection", new
            {
                reason = "NullRecipe"
            });
            return Task.FromResult<PositioningBlockResult<TOutput>>(
                new PositioningBlockFailure<TOutput>(
                    PositioningBlockFailureCategory.InvalidRecipe,
                    "recipe"));
        }
        RulePositioningForensicCapture.Record("recipe-execution", "recipe-start", new
        {
            rootKind = recipe.PlanRoot.Kind
        });
        return EvaluateNodeAsync(recipe.PlanRoot, context, "root", cancellationToken);
    }

    /// <summary>
    /// Evaluates children in declaration order and invokes the parent only after all succeed.
    /// </summary>
    private static async Task<PositioningBlockResult<TOutput>> EvaluateNodeAsync(
        PositioningRecipeNode<TContext, TOutput> node,
        TContext context,
        string path,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RulePositioningForensicCapture.Record("recipe-execution", "block-entry", new
        {
            path,
            node.Kind,
            childKinds = node.Children.Select(child => child.Kind).ToList(),
            childCount = node.Children.Count
        });
        List<TOutput> childValues = new(node.Children.Count);
        for (int childIndex = 0; childIndex < node.Children.Count; childIndex++)
        {
            PositioningRecipeNode<TContext, TOutput> child = node.Children[childIndex];
            PositioningBlockResult<TOutput> childResult =
                await EvaluateNodeAsync(child, context, $"{path}/{childIndex}:{child.Kind}", cancellationToken)
                    .ConfigureAwait(false);
            if (childResult is PositioningBlockFailure<TOutput> childFailure)
            {
                RecordResult(path, node.Kind, childFailure, "ChildFailurePropagated");
                return childResult;
            }
            childValues.Add(((PositioningBlockSuccess<TOutput>)childResult).Value);
        }

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            PositioningBlockResult<TOutput>? result = await node.Block
                .EvaluateAsync(context, childValues.AsReadOnly(), cancellationToken)
                .ConfigureAwait(false);
            PositioningBlockResult<TOutput> finalResult = result ?? UnexpectedFailure(node.Kind);
            RecordResult(path, node.Kind, finalResult, result == null ? "NullResult" : "Evaluated");
            return finalResult;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            PositioningBlockFailure<TOutput> failure = UnexpectedFailure(node.Kind);
            RulePositioningForensicCapture.Record("recipe-execution", "block-exception", new
            {
                path,
                node.Kind,
                exceptionType = exception.GetType().FullName
            });
            RecordResult(path, node.Kind, failure, "UnexpectedException");
            return failure;
        }
    }

    private static void RecordResult(
        string path,
        string blockKind,
        PositioningBlockResult<TOutput> result,
        string reason)
    {
        object payload = result switch
        {
            PositioningBlockFailure<TOutput> failure => (object)new
            {
                path,
                blockKind,
                result = "Failure",
                reason,
                category = failure.Category.ToString(),
                failure.OriginatingBlockKind
            },
            _ => (object)new
            {
                path,
                blockKind,
                result = "Success",
                reason,
                category = (string?)null,
                OriginatingBlockKind = (string?)null
            }
        };
        RulePositioningForensicCapture.Record("recipe-execution", "block-result", payload);
    }

    /// <summary>
    /// Converts unexpected implementation failures into a safe typed result.
    /// </summary>
    private static PositioningBlockFailure<TOutput> UnexpectedFailure(string blockKind)
    {
        return new PositioningBlockFailure<TOutput>(
            PositioningBlockFailureCategory.UnexpectedExecutionFailure,
            blockKind);
    }
}
