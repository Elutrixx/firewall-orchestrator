using FWO.Data;
using FWO.Data.Workflow;
using Newtonsoft.Json.Linq;

namespace FWO.Services.RulePositioning.Diagnostics;

/// <summary>Allow-listed projections for domain objects that also carry credentials or large navigation data.</summary>
public static class RulePositioningForensicProjection
{
    /// <summary>Projects the target gateway without its management credential navigation.</summary>
    public static object? Device(Device? device)
    {
        try
        {
            return device == null ? null : new
            {
                device.Id,
                device.Uid,
                device.Name,
                deviceType = DeviceType(device.DeviceType),
                managementId = device.Management?.Id,
                device.LocalRulebase,
                device.GlobalRulebase,
                device.GlobalRulebaseUid,
                device.Package,
                rulebaseLinks = (device.RulebaseLinks ?? []).Select(link => new
                {
                    link.GatewayId,
                    link.FromRuleId,
                    link.FromRulebaseId,
                    link.NextRulebaseId,
                    link.LinkType,
                    link.IsInitial,
                    link.IsGlobal,
                    link.IsSection,
                    link.Created,
                    link.Removed
                }).ToList()
            };
        }
        catch (Exception exception)
        {
            return ProjectionFailure(exception);
        }
    }

    /// <summary>Projects management identity and topology fields while excluding both credentials.</summary>
    public static object? Management(Management? management)
    {
        try
        {
            return management == null ? null : new
            {
                management.Id,
                management.Uid,
                management.Name,
                deviceType = DeviceType(management.DeviceType),
                management.SuperManagerId,
                management.IsSupermanager,
                management.DomainUid,
                management.CloudSubscriptionId,
                management.CloudTenantId,
                management.RulebaseName,
                management.RulebaseUid,
                management.RelevantImportId
            };
        }
        catch (Exception exception)
        {
            return ProjectionFailure(exception);
        }
    }

    /// <summary>Projects a request task while replacing its credential-bearing management navigation.</summary>
    public static object? RequestTask(WfReqTask? task)
    {
        if (task == null)
        {
            return null;
        }
        try
        {
            JObject projected = JObject.FromObject(task);
            projected.Remove("on_management");
            projected["on_management"] = task.OnManagement == null
                ? JValue.CreateNull()
                : JToken.FromObject(Management(task.OnManagement)!);
            return projected;
        }
        catch (Exception exception)
        {
            return ProjectionFailure(exception);
        }
    }

    /// <summary>Projects an entire ticket slice without credential-bearing management objects.</summary>
    public static object? RequestTasks(IEnumerable<WfReqTask>? tasks)
    {
        try
        {
            return tasks?.Select(RequestTask).ToList();
        }
        catch (Exception exception)
        {
            return ProjectionFailure(exception);
        }
    }

    private static object? DeviceType(DeviceType? deviceType)
    {
        return deviceType == null ? null : new
        {
            deviceType.Id,
            deviceType.Name,
            deviceType.Version,
            deviceType.Manufacturer,
            deviceType.IsPureRoutingDevice,
            deviceType.IsManagement,
            deviceType.SupportsRuleHits
        };
    }

    private static object ProjectionFailure(Exception exception) => new
    {
        projectionFailed = true,
        exceptionType = exception.GetType().FullName
    };
}
