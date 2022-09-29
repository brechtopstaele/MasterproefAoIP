package GUI;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.block.BlockBorder;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.chart.ui.ApplicationFrame;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.time.DynamicTimeSeriesCollection;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.Second;

import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.List;

public class StatPlot extends ApplicationFrame {
    static List<Integer> dataList;

    public StatPlot(String title, List<Integer> datalist) {
        super(title);
        this.dataList = datalist;
        DynamicTimeSeriesCollection dataset = createDataset();
        JFreeChart chart = createChart(dataset);
        ChartPanel chartPanel = new ChartPanel(chart, false);
        chartPanel.setFillZoomRectangle(true);
        chartPanel.setMouseWheelEnabled(true);
        chartPanel.setPreferredSize(new Dimension(500, 270));
        setContentPane(chartPanel);
    }

    private static DynamicTimeSeriesCollection createDataset() {
        DynamicTimeSeriesCollection dataset = new DynamicTimeSeriesCollection(1,100, new Second());
        dataset.setTimeBase(new Second(0, 0, 0, 7, 9, 2022));
        for (int j=0; j < dataList.size(); j++) {
            dataset.addValue(0, j, dataList.get(j));
        }
        return dataset;
    }

    private static JFreeChart createChart(DynamicTimeSeriesCollection dataset) {
        JFreeChart chart = ChartFactory.createXYLineChart("Jitter", "Time", "Jitter (ms)", dataset);
        chart.addSubtitle(new TextTitle("Time to generate 1000 charts in SVG "
                + "format (lower bars = better performance)"));
        chart.setBackgroundPaint(Color.WHITE);
        XYPlot plot = chart.getXYPlot();

        DateAxis axis = (DateAxis) plot.getDomainAxis();
        axis.setFixedAutoRange(10000);
        axis.setDateFormatOverride(new SimpleDateFormat("ss.SS"));
        return chart;
    }
}
