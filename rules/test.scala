object ReportGenerator {

  class SinkInfo(val id: Long,
                 val filename: String,
                 val name: String,
                 val line: Int)

  class FlowStep(val id: Long,
                 val function: String,
                 val filename: String,
                 val line: Int)

  class Report(val sink: SinkInfo,
               val flows: List[List[FlowStep]],
               val codes: Map[String, String])

  def run(): String = {
    val sinkCalls = cpg.call.where(_.nameExact(
      List(
        "exec", "system", "popen", "Runtime.exec", "ProcessBuilder.start",
        "writeFileSync", "createWriteStream", "Files.write", "BufferedWriter.write",
        "send", "sendBytes", "sendMessage", "Socket.write", "OutputStream.write",
        "executeQuery", "executeUpdate", "prepareStatement", "createStatement", "all",
        "ObjectOutputStream.writeObject", "HttpURLConnection.connect", "URLConnection.getOutputStream", "get",
        "fork", "spawn", "execvp", "parse"
      )*
    )).toList

    val reports = sinkCalls.map { sink =>

      val flows = sink.traversal.reachableByFlows(cpg.method.parameter).l

      val rawFlows: List[List[FlowStep]] = flows.map { flow =>
        flow.elements.collect {
          case cfgNode: CfgNode =>
            val methodName = cfgNode.method.name
            val fileName   = cfgNode.file.name.l.headOption.getOrElse("N/A")
            val lineNum    = cfgNode.lineNumber.getOrElse(-1)
            new FlowStep(cfgNode.id, methodName, fileName, lineNum)
        }.foldLeft(List.empty[FlowStep]) { (acc, cur) =>
          if (acc.nonEmpty && acc.last.function == cur.function && acc.last.filename == cur.filename) acc
          else acc :+ cur
        }
      }

      // ---- suffix 제거 ----
      def isSuffixOf(smaller: List[FlowStep], bigger: List[FlowStep]): Boolean = {
        val s = smaller.map(_.function)
        val b = bigger.map(_.function)
        b.endsWith(s) && b.size > s.size
      }
      val filteredFlows = rawFlows.filterNot { p =>
        rawFlows.exists(other => other != p && isSuffixOf(p, other))
      }

      // ---- 코드 매핑 ----
      val codes: Map[String, String] =
        Map(sink.id.toString -> sink.code) ++
          filteredFlows.flatMap(flow =>
            flow.map(step => {
              val m = cpg.method.nameExact(step.function).headOption
              step.id.toString -> m.map(_.code).getOrElse(step.function)
            })
          ).toMap

      // ---- Report 구성 ----
      val sinkInfo = new SinkInfo(
        sink.id,
        sink.file.name.l.headOption.getOrElse("N/A"),
        sink.name,
        sink.lineNumber.getOrElse(-1)
      )

      new Report(sinkInfo, filteredFlows, codes)
    }

    val wrapped = Map("reports" -> reports)
    wrapped.toJson
  }
}