package GUI;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.util.List;

public class Graph extends JPanel {
    //initialize coordinates
    List<Integer> cord;
    int marg = 60;

    public Graph(List<Integer> dataList){
        cord = dataList;
    }

    protected void paintComponent(Graphics grf){
        //create instance of the Graphics to use its methods
        super.paintComponent(grf);
        Graphics2D graph = (Graphics2D)grf;

        //Sets the value of a single preference for the rendering algorithms.
        graph.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        // get width and height
        int width = getWidth();
        int height = getHeight();

        // draw graph
        graph.draw(new Line2D.Double(marg, marg, marg, height-marg));
        graph.draw(new Line2D.Double(marg, height-marg, width-marg, height-marg));

        //find value of x and scale to plot points
        double x = (double)(width-2*marg)/(cord.size()-1);
        double scale = (double)(height-2*marg)/getMax();

        //set color for points
        graph.setPaint(Color.RED);

        // set points to the graph
        for(int i=0; i<cord.size(); i++){
            double x1 = marg+i*x;
            double y1 = height-marg-scale*cord.get(i);
            graph.fill(new Ellipse2D.Double(x1-2, y1-2, 4, 4));
        }
    }

    //create getMax() method to find maximum value
    private int getMax(){
        int max = -Integer.MAX_VALUE;
        for(int i=0; i<cord.size(); i++){
            if(cord.get(i)>max)
                max = cord.get(i);

        }
        return max;
    }
}
