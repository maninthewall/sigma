# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, juju4

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import json
import sigma
from sigma.parser.condition import ConditionOR
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
# Sumo specifics
# https://help.sumologic.com/05Search/Search-Query-Language
# want _index or _sourceCategory for performance
# try to get most string match on first line for performance
# further sorting can be done with extra parsing
# No regex match, must use 'parse regex' https://help.sumologic.com/05Search/Search-Query-Language/01-Parse-Operators/02-Parse-Variable-Patterns-Using-Regex
# For some strings like Windows ProcessCmdline or LogonProcess, it might be good to force case lower and upper as Windows is inconsistent in logs


class SumoLogicBackend(SingleTextQueryBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into SumoLogic query"""
    identifier = "sumologic"
    active = True
    config_required = False
    default_config = ["sysmon", "sumologic"]
    supported_alert_methods = {'email', 'http_post'}

    options = SingleTextQueryBackend.options + (
        ("alert_methods", "", "Alert method(s) to use when the rule triggers, comma separated. Supported: " + ', '.join(supported_alert_methods), None),

        # Options for Webhook alerting
        ("webhook_notification", False, "Use webhooks for notification", None),
        ("webhook_id", None, "Sumologic webhook ID number", None),
        ("webhook_payload", None, "Sumologic webhook payload", None),
        ("description_include_rule_metadata", False, "Indicates if the description should contain the metadata about the rule which triggered", None),

        # Options for Email alerting
        ("email_notification", None, "Who to email", None),
        ("mute_errors", False, "Mute error emails, defaults to False", None),

        # Options for Index override
        ("index_field", "_index", "Index field [_index, _sourceCategory, _view]", None),

        # Options for output
        ("output", "plain", "Output format:  json = to output in Sumologic Content API json format | plain = output query only", None),

        # Other options
        ("timezone", "Etc/UTC", "Default timezone for search", None),
        ("itemize_alerts", False, "Send a separate alert for each search result. Default False", None),
        ("max_itemized_alerts", 50, "Maximum number of alerts to send for each search result. Default 50", None),
        ("minimum_interval", "15m", "Minimum interval supported for scheduled queries", None),
        ("use_fields", False, "Output fields command. Default False", None),
        )

    index_field = "_index"
    reClear = None
    andToken = " AND "
    orToken = " OR "
    notToken = "!"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isEmpty(%s)"
    notNullExpression = "!isEmpty(%s)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    interval = None
    logname = None
    fields = None 
    aggregates = list() 

    def generateAggregation(self, agg):
        # lnx_shell_priv_esc_prep.yml
        # print("DEBUG generateAggregation(): %s, %s, %s, %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, str(agg)))
        # Below we defer output of the actual aggregation commands until the rest of the query is built.  
        # We do this because aggregation commands like count will cause data to be lost that isn't counted
        # and we want all search terms/query conditions processed first before we aggregate.
        if agg.groupfield == 'host':
            agg.groupfield = 'hostname'
        if agg.aggfunc_notrans == 'count() by':
            agg.aggfunc_notrans = 'count'
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            agg.aggfunc_notrans = 'count'
            # WIP
            # ex:
            # (QUERY) | timeslice 5m
            # | count by _timeslice,process,hostname
            # | where _count > 5
            current_agg = " | timeslice %s | %s by %s | where _count > 0" % (self.interval, agg.aggfunc_notrans, "_timeslice," + agg.current[0] )
            self.aggregates.append(current_agg)
            return ""
            #return " | timeslice %s | count_distinct(%s) %s | where _count_distinct %s %s" % (self.interval, agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)
        elif not agg.groupfield:
            # return " | %s(%s) | when _count %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
            current_agg = " | %s by %s | where _count %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
            self.aggregates.append(current_agg)
            return "" 
        elif agg.groupfield:
            result_field = "_count"
            if agg.aggfield:
                func="%s(%s) by %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield)
            else:
                func="%s(%s) by %s" % (agg.aggfunc_notrans, agg.groupfield, agg.groupfield)
            if agg.aggfunc_notrans == "sum":
                result_field = "_sum"
            current_agg = " | %s |  where %s %s %s" % (func, result_field, agg.cond_op, agg.condition)
            self.aggregates.append(current_agg)
            return "" 
        else:
            current_agg = " | %s(%s) by %s | where _count %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)
            self.aggregates.append(current_agg)
            return "" 

    def generateBefore(self, parsed):
        # not required but makes query faster, especially if no FER or _index/_sourceCategory
        if self.logname:
            return "%s " % self.logname
        return ""

    def generate(self, sigmaparser):
        rulename = self.getRuleName(sigmaparser)
        title = sigmaparser.parsedyaml.setdefault("title", "")
        description = sigmaparser.parsedyaml.setdefault("description", "No Description")
        false_positives = sigmaparser.parsedyaml.setdefault("falsepositives", "")
        level = sigmaparser.parsedyaml.setdefault("level", "")
        rule_tag = sigmaparser.parsedyaml.setdefault("tags", ["NOT-DEF"])
        # Get time frame if exists otherwise set it to 15 minutes
        interval = sigmaparser.parsedyaml["detection"].setdefault("timeframe", "15m")

        try:
            self.product = sigmaparser.parsedyaml['logsource']['product']   # OS or Software
        except KeyError:
            self.product = None
        try:
            self.service = sigmaparser.parsedyaml['logsource']['service']   # Channel
        except KeyError:
            self.service = None
        try:
            self.category = sigmaparser.parsedyaml['logsource']['category']   # Channel
        except KeyError:
            self.category = None
        # FIXME! don't get backend config mapping
        self.indices = sigmaparser.get_logsource().index
        if len(self.indices) == 0:
            self.indices = None
        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass

        result = ""

        columns = list()
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                if type(mapped) == str:
                    columns.append(mapped)
                elif type(mapped) == list:
                    columns.extend(mapped)
                else:
                    raise TypeError("Field mapping must return string or list")
        except KeyError:    # no 'fields' attribute
            pass

        if columns:
            self.fields = " | fields " + ",".join(columns)


        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            # FIXME! exclude if expression is regexp but anyway, not directly supported.
            #   Not doing if aggregation ('| count') or key ('=')
            if not (query.startswith('"') and query.endswith('"')) and not (query.startswith('(') and query.endswith(')')) and not ('|' in query) and not ('=' in query):
                query = '"%s"' % query
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            if before is not None and before is not "":
                result = before
            if query is not None:
                if result is not "":
                    result += " OR " + query
                else:
                    result = query
            if after is not None:
                result += after

        self.queries[rulename] = dict()
        self.queries[rulename]['name'] = rulename 
        self.queries[rulename]['description'] = description if description else "No Description"
        self.queries[rulename]['title'] = title
        self.queries[rulename]['interval'] = self.interval

        # adding parenthesis here in case 2 rules are aggregated together - ex: win_possible_applocker_bypass
        # but does not work if count, where or other piped statements...

        if '|' in result:
            self.queries[rulename]['query'] = result
        else:
            self.queries[rulename]['query'] = '('+ result + ')'

        # if fields are specified 
        # output them using the Sumologic 'fields' commmand at the end of the current query
        # if there are aggregates, dont output this field because it may cause data that is
        # needed for an aggregation to be lost
        if self.use_fields and self.fields and not self.aggregates:
            self.queries[rulename]['query'] = self.queries[rulename]['query'] + self.fields
            self.fields = None 

        # if aggregates were specified
        # output them last in the query because Sumologic aggregates are lossy operations and 
        # you generally want them toward the end of a query
        if self.aggregates:
            # WIP
            # Consider adding any fields listed in the 'columns' to each 'count by' commands

            # deduplicate any aggregates
            aggs = list(set(self.aggregates))
            temp = self.queries[rulename]['query'] + "".join(aggs) 
            self.queries[rulename]['query'] = temp 
            self.aggregates.clear()

        # We'll output all queries in finalise()
        return


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO/FIXME! depending on deployment configuration, existing FER must be populate here (or backend config?)
        # aFL = ["EventID"]
        self.queries = dict()
        aFL = ["_index", "_sourceCategory", "_view", "EventID", "sourcename", "CommandLine", "NewProcessName", "Image", "ParentImage", "ParentCommandLine", "ParentProcessName"]
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    # def generateCleanValueNodeLogsource(self, value):
    #    return self.valueExpression % (self.cleanValue(str(value)))

    # Clearing values from special characters.
    # Sumologic: only removing '*' (in quotes, is litteral. without, is wildcard) and '"'
    def CleanNode(self, node):
        search_ptrn = re.compile(r"[*\"\\]")
        replace_ptrn = re.compile(r"[*\"\\]")
        match = search_ptrn.search(str(node))
        new_node = list()
        if match:
            replaced_str = replace_ptrn.sub('*', node)
            node = [x for x in replaced_str.split('*') if x]
            new_node.extend(node)
        else:
            new_node.append(node)
        node = new_node
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key in self.allowedFieldsList:
            if not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if key in ("LogName", "source"):
                    self.logname = value
                # need cleanValue if sigma entry with single quote
                return self.mapExpression % (key, self.cleanValue(value, key))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            elif type(value) == SigmaRegularExpressionModifier:
                regex = str(value)
                return " where %s matches /%s/" % (key, self.generateValueNode(regex))
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            if not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if type(value) is str:
                    new_value = list()
                    value = self.CleanNode(value)
                    if type(value) == list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                    else:
                        new_value.append(value)
                    if len(new_value) == 1:
                        if self.generateANDNode(new_value):
                            return "(" + self.generateANDNode(new_value) + ")"
                        else:
                            # if after cleaning node, it is empty but there is AND statement... make it true.
                            return "true"
                    else:
                        return "(" + self.generateORNode(new_value) + ")"
                else:
                    return self.generateValueNode(value)
            elif type(value) is list:
                new_value = list()
                for item in value:
                    item = self.CleanNode(item)
                    if type(item) is list and len(item) == 1:
                        new_value.append(self.valueExpression % item[0])
                    elif type(item) is list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in item]))
                    else:
                        new_value.append(item)
                return self.generateORNode(new_value)
            elif type(value) == SigmaRegularExpressionModifier:
                regex = str(value)
                return " | where %s matches /%s/" % (key, self.generateValueNode(regex))
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # from mixins.py
    # input in simple quotes are not passing through this function. ex: rules/windows/sysmon/sysmon_vul_java_remote_debugging.yml, rules/apt/apt_sofacy_zebrocy.yml
    #   => OK only if field entry with list, not string
    #   => generateNode: call cleanValue
    def cleanValue(self, val, key=''):
        # in sumologic, if key, can use wildcard outside of double quotes. if inside, it's litteral
        if key:
            # EXPERIMENTAL: if asterisk is all by itself, we can leave it be I think
            if val == '*':
                return val
            val = re.sub(r'\"', '\\"', str(val))
            val = re.sub(r'(.+)\*(.+)', '"\g<1>"*"\g<2>"', val, 0)
            val = re.sub(r'^\*', '*"', val)
            val = re.sub(r'\*$', '"*', val)
            # if unbalanced wildcard?
            if val.startswith('*"') and not (val.endswith('"*') or val.endswith('"')):
                val = val + '"'
            if val.endswith('"*') and not (val.startswith('*"') or val.startswith('"')):
                val = '"' + val
            # double escape if end quote
            if val.endswith('\\"*') and not val.endswith('\\\\"*'):
                val = re.sub(r'\\"\*$', '\\\\\\"*', val)
        # if not key and not (val.startswith('"') and val.endswith('"')) and not (val.startswith('(') and val.endswith(')')) and not ('|' in val) and val:
        # apt_babyshark.yml
        if not (val.startswith('"') and val.endswith('"')) and not (val.startswith('(') and val.endswith(')')) and not ('|' in val) and not ('*' in val) and val and not '_index' in key and not '_sourceCategory' in key and not '_view' in key:
            val = '"%s"' % val
        return val

    # for keywords values with space
    def generateValueNode(self, node, key=''):
        cV = self.cleanValue(str(node), key)
        if type(node) is int:
            return cV
        if 'AND' in node and cV:
            return "(" + cV + ")"
        else:
            return cV

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (key, self.generateValueNode(item, key)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return "(" + " OR ".join(itemslist) + ")"

    # generateORNode algorithm for ArcSightBackend & SumoLogicBackend class.
    def generateORNode(self, node):
        if type(node) == ConditionOR and all(isinstance(item, str) for item in node):
            new_value = list()
            for value in node:
                value = self.CleanNode(value)
                if type(value) is list:
                    new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                else:
                    new_value.append(value)
            return "(" + self.orToken.join([self.generateNode(val) for val in new_value]) + ")"
        return "(" + self.orToken.join([self.generateNode(val) for val in node]) + ")"

    def generateScheduleInfo(self, interval):
        m = re.match("(?i)(\d+)s", interval)
        if m:
            interval = self.minimum_interval

        m = re.match("(?i)(\d+)([d|h|m])", interval)
        if m:
            integer_interval = m.group(1)
            interval_type = m.group(2)
        else:
            raise NotImplementedError("interval format '%s' not supported.  format: \d[d|h|m]" % interval)

        if interval_type.lower() == "m":
            if int(integer_interval) < 15:
		# minimum Sumologic query interval is 15 minutes
		# raise anything less than that up to the minimum
                integer_interval = "15"
            return "0 0/%s * * * ? *" % (integer_interval), "%sMinutes" % integer_interval, "%sm" % integer_interval
        elif interval_type.lower() == "h":
            hour= "Hour"
            if int(integer_interval) > 1 and int(integer_interval) < 24:
              hour = "Hours"
            elif integer_interval == "24":
                return "0 0 12 1/1 * ? *", "1Day", "%sh" % integer_interval
            return "0 0 0/%s * * ? *" % (integer_interval), "%s%s" % (integer_interval, hour), "%sh" % integer_interval
        elif interval_type.lower() == "d":
            return "0 0 12 ? * 1,2,3,4,5,6,7", "1Day", "%sd" % integer_interval


    def finalize(self):
        result = list() 
        titles = set()

        def getTitle(title):
            title = title.replace('\n','')
            if title in titles:   # add counter if name collides
                cnt = 2
                while "%s-%d" % (title, cnt) in titles:
                    cnt += 1
                title = "%s-%d" % (title, cnt)
            titles.add(title)
            return title

        if self.webhook_notification:
            notification = {
                "taskType": "WebhookSearchNotificationSyncDefinition",
                "webhookId": self.webhook_id,
                "payload": self.webhook_payload,
                "itemizeAlerts": self.itemize_alerts,
                "maxItemizedAlerts": self.max_itemized_alerts
            }
        elif self.email_notification:
            notification = {
                "taskType": "EmailSearchNotificationSyncDefinition",
                "toList": [
                    "{to}"
                ],
                "subjectTemplate": "Search Results: {{SearchName}}",
                "includeQuery": True,
                "includeResultSet": True,
                "includeHistogram": True,
                "includeCsvAttachment": True,
            }

        for key, value in self.queries.items():
            rulename = getTitle(value['title']) 
            query = value['query'].replace('\n','')
            description = value['description'].replace('\n','')
            interval = value['interval']

            cronExpression, scheduleType, scheduledInterval = self.generateScheduleInfo(interval)

            if self.output == 'json':
                format_output =  {
                    "type": "SavedSearchWithScheduleSyncDefinition",
                    "name": rulename,
                    "description": description,
                    "search": {
                        "queryText": query,
                        "defaultTimeRange": "-%s" % scheduledInterval,
                        "byReceiptTime": False,
                        "viewName": "",
                        "viewStartTime": "1970-01-01T00:00:00Z",
                        "queryParameters": [],
                        "parsingMode": "AutoParse"
                    },
                    "searchSchedule": {
                        "cronExpression": cronExpression,
                        "displayableTimeRange": "-%s" % scheduledInterval,
                        "parseableTimeRange": {
                            "type": "BeginBoundedTimeRange",
                            "from": {
                                "relativeTime": "-%s" % scheduledInterval,
                                "type": "RelativeTimeRangeBoundary"
                            },
                            "to": None,
                        },
                        "notification": None,
                        "timeZone": self.timezone,
                        "threshold": {
                            "thresholdType": "group",
                            "operator": "gt",
                            "count": 0
                        },
                        "muteErrorEmails": self.mute_errors,
                        "scheduleType": scheduleType,
                        "parameters": []
                    }
                }
                format_output['searchSchedule']['notification'] = notification
                result.append(json.dumps(format_output, indent=4))
            elif self.output == 'plain':
                result.append(query)
            else:
                raise NotImplementedError("Output type '%s' not supported" % self.output_type)

        return '\n'.join(result)
