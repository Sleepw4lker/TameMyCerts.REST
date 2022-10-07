// Copyright 2022 Uwe Gradenegger

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Diagnostics;
using System.Reflection;
using System.Security;

namespace AdcsToRest
{
    /// <summary>
    ///     A simple class to write to the Windows Event log.
    /// </summary>
    public static class Logger
    {
        /// <summary>
        ///     Logs an exception to the Windows Application Event log.
        /// </summary>
        /// <param name="ex"></param>
        public static void Log(Exception ex)
        {
            const string logName = "Application";

            var assembly = Assembly.GetExecutingAssembly();

            var eventLog = new EventLog(logName)
            {
                Source = CreateEventSource(
                    ((AssemblyTitleAttribute) assembly.GetCustomAttribute(typeof(AssemblyTitleAttribute))).Title,
                    logName)
            };

            eventLog.WriteEntry(string.Format(LocalizedStrings.DESC_UNHANDLED_EXCEPTION, ex.Message, ex),
                EventLogEntryType.Error, 1);
        }

        private static string CreateEventSource(string currentAppName, string logName)
        {
            var eventSource = currentAppName;

            try
            {
                if (!EventLog.SourceExists(eventSource))
                {
                    EventLog.CreateEventSource(eventSource, logName);
                }
            }
            catch (SecurityException)
            {
                eventSource = "Application";
            }

            return eventSource;
        }
    }
}