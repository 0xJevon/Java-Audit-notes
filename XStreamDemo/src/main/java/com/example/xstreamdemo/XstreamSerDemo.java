package com.example.xstreamdemo;

import com.thoughtworks.xstream.XStream;

public class XstreamSerDemo {
    public static void main(String[] args) {
        Car car = new Car("Ferrari", 4000000);
        XStream xStream = new XStream();
        //序列化数据
        String xml = xStream.toXML(car);
        System.out.print(xml);
        //反序列化数据
//        xStream.fromXML(xml);
       //com.sun.rowset.JdbcRowSetImpl
        //java.util.PriorityQueue
    }
}
